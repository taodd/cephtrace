#!/usr/bin/env python3
"""Extract GNU build-ids for every (distro, version, module) referenced by the
dwarf JSON files under files/. Writes a CSV with one row per module.

Strategy:
  * Group the JSON inventory by (distro, version), unioning the modules
    each tool requires for that version.
  * Resolve the runtime binary package per module:
       ceph-osd            -> ceph-osd / ceph-osd
       librados.so.2       -> librados2 / librados2
       librbd.so.1         -> librbd1 / librbd1
       libceph-common.so.2 -> ceph-common / ceph-base
  * Fetch the runtime deb/rpm from launchpad / UCA mirror / snapshot.debian /
    download.ceph.com, extract just the target ELF, and run `readelf -n` to
    pull the build-id out of .note.gnu.build-id.
  * Cache downloads under /tmp/buildid_work so re-runs are cheap.

Output: build_ids.csv with columns
    distro,version,module,package,arch,build_id,source_url
"""

from __future__ import annotations

import csv
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FILES_DIR = ROOT / "files"
CSV_OUT = ROOT / "build_ids.csv"
WORK_DIR = Path("/tmp/buildid_work")
WORK_DIR.mkdir(parents=True, exist_ok=True)
CACHE_DIR = WORK_DIR / "cache"
CACHE_DIR.mkdir(exist_ok=True)

ARCH = "amd64"   # debs
RPM_ARCH = "x86_64"

# Module name -> (deb package, rpm package, in-archive file relpath glob)
# We search for the file inside the extracted package tree.
MODULE_INFO = {
    "ceph-osd": {
        "deb_pkg": "ceph-osd",
        "rpm_pkg": "ceph-osd",
        "file_globs": ["usr/bin/ceph-osd"],
    },
    "librados.so.2": {
        "deb_pkg": "librados2",
        "rpm_pkg": "librados2",
        "file_globs": [
            "usr/lib/*/librados.so.2.*",
            "usr/lib64/librados.so.2.*",
        ],
    },
    "librbd.so.1": {
        "deb_pkg": "librbd1",
        "rpm_pkg": "librbd1",
        "file_globs": [
            "usr/lib/*/librbd.so.1.*",
            "usr/lib64/librbd.so.1.*",
        ],
    },
    "libceph-common.so.2": {
        # Ships inside librados2 on both deb (jammy/noble) and rpm (el9) for
        # all Quincy+ versions in files/. Old Octopus shipped it via ceph-base
        # (rpm) / ceph-common (deb) — handled by per-distro fallback below.
        "deb_pkg": "librados2",
        "rpm_pkg": "librados2",
        "file_globs": [
            "usr/lib/*/ceph/libceph-common.so.2",
            "usr/lib/*/ceph/libceph-common.so.2.*",
            "usr/lib64/ceph/libceph-common.so.2",
            "usr/lib64/ceph/libceph-common.so.2.*",
        ],
    },
}

CSV_HEADER = ["distro", "version", "module", "package", "arch", "build_id", "source_url"]


def log(msg: str) -> None:
    print(msg, flush=True)


def load_inventory():
    """Yield (distro, tool, version, [modules]) tuples from every JSON."""
    out = []
    for distro_dir in sorted(FILES_DIR.iterdir()):
        if not distro_dir.is_dir():
            continue
        for tool_dir in sorted(distro_dir.iterdir()):
            if not tool_dir.is_dir():
                continue
            for f in sorted(tool_dir.glob("*.json")):
                d = json.loads(f.read_text())
                ver = d["version"]
                mods = [k for k in d if k in MODULE_INFO]
                out.append((distro_dir.name, tool_dir.name, ver, mods))
    return out


def group_by_version(inv):
    """Return {(distro, version): {module, ...}}."""
    g = {}
    for distro, tool, ver, mods in inv:
        key = (distro, ver)
        g.setdefault(key, set()).update(mods)
    return g


# --------------------------------------------------------------------------- #
# Download resolution                                                          #
# --------------------------------------------------------------------------- #

def http_head_ok(url: str, timeout: float = 30.0) -> bool:
    try:
        req = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return 200 <= r.status < 400
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ConnectionError):
        return False


def http_get(url: str, timeout: float = 120.0, retries: int = 4) -> bytes:
    last = None
    for i in range(retries):
        try:
            with urllib.request.urlopen(url, timeout=timeout) as r:
                return r.read()
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as e:
            last = e
            code = getattr(e, "code", None)
            if code == 404:
                raise
            import time as _t
            _t.sleep(2 ** i)
    raise last  # type: ignore[misc]


def cached_download(url: str) -> Path:
    """Download url to cache (skip if present). Return local path."""
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", url)
    dest = CACHE_DIR / name
    if dest.exists() and dest.stat().st_size > 0:
        return dest
    tmp = dest.with_suffix(dest.suffix + ".part")
    log(f"    fetching {url}")
    with urllib.request.urlopen(url, timeout=600) as r, open(tmp, "wb") as f:
        shutil.copyfileobj(r, f)
    tmp.rename(dest)
    return dest


# Cache: (distro, version) -> resolved base url for that distro's mirror
_resolved_base: dict[tuple[str, str], str | None] = {}


def resolve_ubuntu_lp_base(version: str, arch: str = ARCH) -> str | None:
    """Scrape launchpad source page, return the first +build/.../+files dir
    that actually hosts a ceph-osd .deb at this arch (i.e. the matching build).
    """
    src_page = f"https://launchpad.net/ubuntu/+source/ceph/{version}"
    try:
        html = http_get(src_page).decode("utf-8", "replace")
    except Exception as e:
        log(f"  launchpad source page failed: {e}")
        return None
    paths = sorted(set(re.findall(r"/[^\"]+/\+build/[0-9]+", html)))
    for p in paths:
        probe = f"https://launchpad.net{p}/+files/ceph-osd_{version}_{arch}.deb"
        if http_head_ok(probe):
            return f"https://launchpad.net{p}/+files"
    return None


def resolve_uca_base() -> str:
    # Most ~cloudX uploads land in this flat pool eventually.
    return "https://ubuntu-cloud.archive.canonical.com/ubuntu/pool/main/c/ceph"


# UCA PPAs to query for ~cloud0 versions that never made it (or no longer
# live) in the flat pool. Ordered by likelihood, newest first.
_UCA_PPAS = [
    "yoga-staging", "yoga-proposed", "yoga-updates",
    "zed-staging", "zed-proposed", "zed-updates",
    "antelope-staging", "antelope-proposed", "antelope-updates",
    "bobcat-staging", "bobcat-proposed", "bobcat-updates",
    "caracal-staging", "caracal-proposed", "caracal-updates",
    "dalmatian-staging", "dalmatian-proposed", "dalmatian-updates",
    "epoxy-staging", "epoxy-proposed", "epoxy-updates",
    "flamingo-devel", "flamingo-staging",
    "flamingo-proposed", "flamingo-updates",
]


def resolve_uca_ppa_url(version: str, deb_pkg: str, arch: str = ARCH) -> str | None:
    """Query the Launchpad API across UCA PPAs to find a published binary for
    this (deb_pkg, version, arch) and return its build's +files download URL.
    Build artefacts on Launchpad persist even after a publication is removed,
    so this works for superseded uploads too.
    """
    api = "https://api.launchpad.net/devel/~ubuntu-cloud-archive/+archive/ubuntu/{ppa}"
    q = urllib.parse.urlencode({
        "ws.op": "getPublishedBinaries",
        "binary_name": deb_pkg,
        "version": version,
        "exact_match": "true",
    })
    arch_suffix = f"/{arch}"
    for ppa in _UCA_PPAS:
        url = api.format(ppa=ppa) + "?" + q
        try:
            data = json.loads(http_get(url, timeout=30).decode("utf-8"))
        except urllib.error.HTTPError:
            continue
        except Exception:
            continue
        for e in data.get("entries", []):
            das = e.get("distro_arch_series_link", "")
            if not das.endswith(arch_suffix):
                continue
            build_link = e.get("build_link") or ""
            # Convert .../+archive/.../+build/<id> -> launchpad.net/.../+build/<id>/+files/<deb>
            m = re.search(r"/~ubuntu-cloud-archive/\+archive/ubuntu/[^/]+/\+build/(\d+)", build_link)
            if not m:
                continue
            return (f"https://launchpad.net/~ubuntu-cloud-archive/+archive/ubuntu/{ppa}"
                    f"/+build/{m.group(1)}/+files/{deb_pkg}_{version}_{arch}.deb")
    return None


def resolve_debian_url(version: str, pkg: str, arch: str = ARCH) -> str | None:
    """Use snapshot.debian.org's JSON API to locate the .deb for one (pkg,
    version, arch) and return the by-hash file URL (which always resolves).
    """
    # snapshot.debian.org URL-quotes '+' in versions as %2B.
    enc_version = urllib.parse.quote(version, safe="")
    api = (f"https://snapshot.debian.org/mr/binary/{pkg}/{enc_version}/"
           f"binfiles?fileinfo=1")
    try:
        meta = json.loads(http_get(api).decode("utf-8"))
    except Exception as e:
        log(f"  snapshot.debian binfiles({pkg}) failed: {e}")
        return None
    fileinfo = meta.get("fileinfo") or {}
    suffix = f"_{arch}.deb"
    for sha, infos in fileinfo.items():
        for info in infos:
            if (info.get("archive_name") == "debian"
                    and info.get("name", "").endswith(suffix)):
                return f"https://snapshot.debian.org/file/{sha}"
    return None


def resolve_ceph_rpm_base(version_str: str) -> str | None:
    """download.ceph.com keeps per-version dirs `rpm-<x.y.z>/el9/<arch>/` for
    every release point — the floating `rpm-<release>/` dir only mirrors the
    latest. Use the pinned dir so old versions remain reachable.
    """
    clean = version_str.split(":", 1)[-1]                    # drop epoch
    m = re.match(r"(\d+\.\d+\.\d+)", clean)
    if not m:
        return None
    point = m.group(1)
    return f"https://download.ceph.com/rpm-{point}/el9/{RPM_ARCH}"


def candidate_urls(distro: str, version: str, deb_pkg: str, rpm_pkg: str) -> list[str]:
    """Return candidate package URLs to try in order, for this distro+version."""
    if distro == "ubuntu":
        # Try the launchpad build URL first (most reliable, exact version pinned).
        urls: list[str] = []
        cached = _resolved_base.get((distro, version))
        if cached is None and (distro, version) not in _resolved_base:
            cached = resolve_ubuntu_lp_base(version)
            _resolved_base[(distro, version)] = cached
        if cached:
            urls.append(f"{cached}/{deb_pkg}_{version}_{ARCH}.deb")
        # For ~cloudX uploads, also try the UCA pool and (as a last resort)
        # the originating UCA staging/proposed PPA via the Launchpad API.
        if "~cloud" in version:
            urls.append(f"{resolve_uca_base()}/{deb_pkg}_{version}_{ARCH}.deb")
            ppa_url = resolve_uca_ppa_url(version, deb_pkg)
            if ppa_url:
                urls.append(ppa_url)
        return urls
    if distro == "debian":
        u = resolve_debian_url(version, deb_pkg)
        return [u] if u else []
    if distro == "centos-stream":
        cached = _resolved_base.get((distro, version))
        if cached is None and (distro, version) not in _resolved_base:
            cached = resolve_ceph_rpm_base(version)
            _resolved_base[(distro, version)] = cached
        if not cached:
            return []
        # version_str like "2:19.2.3-0.el9" -> "19.2.3-0.el9"
        clean = version.split(":", 1)[-1]
        return [f"{cached}/{rpm_pkg}-{clean}.{RPM_ARCH}.rpm"]
    return []


# --------------------------------------------------------------------------- #
# Extraction + build-id read                                                   #
# --------------------------------------------------------------------------- #

def extract_deb(deb_path: Path, dest: Path) -> bool:
    try:
        subprocess.run(
            ["dpkg-deb", "-x", str(deb_path), str(dest)],
            check=True, capture_output=True,
        )
        return True
    except subprocess.CalledProcessError as e:
        log(f"    dpkg-deb -x failed: {e.stderr.decode(errors='replace')[:200]}")
        return False


def _rpm_payload_offset(rpm_path: Path) -> int:
    """Return the byte offset where the cpio payload begins.

    RPM layout: Lead (96 bytes) + Signature header (padded to 8 bytes) +
    Main header (no padding) + Payload. Each header starts with
    `8e ad e8 01 00 00 00 00`, then big-endian (nIndex, dataLen) at offset 8.
    """
    HDR_MAGIC = b"\x8e\xad\xe8\x01\x00\x00\x00\x00"
    import struct

    def header_size(buf: bytes, off: int) -> int:
        assert buf[off:off + 8] == HDR_MAGIC, f"bad header magic at {off:#x}"
        n_idx, data_len = struct.unpack(">II", buf[off + 8:off + 16])
        return 16 + n_idx * 16 + data_len

    with open(rpm_path, "rb") as f:
        head = f.read(1024 * 1024)
    pos = 96  # past Lead
    sig_size = header_size(head, pos)
    pos += sig_size
    pos = (pos + 7) & ~7   # Signature is padded to 8-byte boundary
    main_size = header_size(head, pos)
    pos += main_size
    return pos


def _decompressor_for(magic: bytes) -> list[str] | None:
    if magic.startswith(b"\x1f\x8b"):
        return ["gzip", "-dc"]
    if magic.startswith(b"\xfd7zXZ\x00"):
        return ["xz", "-dc"]
    if magic.startswith(b"\x28\xb5\x2f\xfd"):
        return ["zstd", "-dcq"]
    if magic.startswith(b"BZ"):
        return ["bzip2", "-dc"]
    return None


def extract_rpm(rpm_path: Path, dest: Path) -> bool:
    """Pure-Python RPM payload extraction (no rpm2cpio needed).
    Skips the RPM Lead + Signature + Main headers, then pipes the payload
    through the matching decompressor into `cpio -idmu`.
    """
    try:
        off = _rpm_payload_offset(rpm_path)
    except Exception as e:
        log(f"    rpm header parse failed: {e!r}")
        return False
    with open(rpm_path, "rb") as f:
        f.seek(off)
        magic = f.read(8)
    decomp = _decompressor_for(magic)
    if decomp is None:
        log(f"    unknown payload magic {magic.hex()}; "
            f"need gzip/xz/zstd/bzip2 on the system")
        return False
    try:
        # Stream: dd if=rpm bs=1 skip=off | <decomp> | cpio -idmu
        with open(rpm_path, "rb") as rf:
            rf.seek(off)
            decomp_p = subprocess.Popen(
                decomp, stdin=rf, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            cpio_p = subprocess.Popen(
                ["cpio", "-idmu", "--quiet"],
                stdin=decomp_p.stdout, cwd=str(dest),
                stderr=subprocess.PIPE,
            )
            decomp_p.stdout.close()
            _, cpio_err = cpio_p.communicate()
            decomp_p.wait()
        if cpio_p.returncode != 0:
            log(f"    cpio failed: {cpio_err.decode(errors='replace')[:200]}")
            return False
        return True
    except (OSError, subprocess.SubprocessError) as e:
        log(f"    rpm extract failed: {e!r}")
        return False


def find_module_file(root: Path, globs: list[str]) -> Path | None:
    """Return first matching ELF (skip symlinks; we want the real file)."""
    for g in globs:
        for p in root.glob(g):
            try:
                resolved = p.resolve()
                if resolved.is_file():
                    return resolved
            except OSError:
                continue
    return None


_BUILDID_RE = re.compile(r"Build ID:\s*([0-9a-fA-F]+)")


def read_build_id(elf: Path) -> str | None:
    try:
        out = subprocess.run(
            ["readelf", "-n", str(elf)],
            check=True, capture_output=True, text=True,
        ).stdout
    except subprocess.CalledProcessError as e:
        log(f"    readelf failed: {e.stderr[:200]}")
        return None
    m = _BUILDID_RE.search(out)
    return m.group(1) if m else None


# --------------------------------------------------------------------------- #
# Per-version worker                                                           #
# --------------------------------------------------------------------------- #

def already_done(seen: set, distro: str, version: str, module: str) -> bool:
    return (distro, version, module) in seen


def process_version(distro: str, version: str, modules: set[str],
                    writer: csv.writer, csv_fh, seen: set) -> None:
    log(f"\n== {distro} / {version} ({', '.join(sorted(modules))})")
    # Group modules by package so we only download each .deb/.rpm once.
    pkg_to_modules: dict[str, list[str]] = {}
    for mod in modules:
        info = MODULE_INFO[mod]
        pkg = info["rpm_pkg"] if distro == "centos-stream" else info["deb_pkg"]
        pkg_to_modules.setdefault(pkg, []).append(mod)

    for pkg, mods in pkg_to_modules.items():
        # Quick skip if every module from this package is already in CSV.
        if all(already_done(seen, distro, version, m) for m in mods):
            log(f"  {pkg}: all modules already in CSV; skip")
            continue
        rpm_pkg = MODULE_INFO[mods[0]]["rpm_pkg"]
        urls = candidate_urls(distro, version, pkg, rpm_pkg)
        if not urls:
            log(f"  {pkg}: no candidate URL (distro={distro})")
            continue

        deb_path: Path | None = None
        used_url: str | None = None
        for url in urls:
            try:
                deb_path = cached_download(url)
                used_url = url
                break
            except (urllib.error.HTTPError, urllib.error.URLError) as e:
                log(f"    {url}: {e}")
        if not deb_path:
            log(f"  {pkg}: download failed (tried {len(urls)})")
            continue

        with tempfile.TemporaryDirectory(prefix="bid_", dir=str(WORK_DIR)) as td:
            tdp = Path(td)
            if distro == "centos-stream":
                ok = extract_rpm(deb_path, tdp)
            else:
                ok = extract_deb(deb_path, tdp)
            if not ok:
                continue

            for mod in mods:
                if already_done(seen, distro, version, mod):
                    continue
                globs = MODULE_INFO[mod]["file_globs"]
                elf = find_module_file(tdp, globs)
                if not elf:
                    log(f"    {mod}: not found in {pkg}")
                    continue
                bid = read_build_id(elf)
                if not bid:
                    log(f"    {mod}: no build-id in {elf.name}")
                    continue
                arch = ARCH if distro != "centos-stream" else RPM_ARCH
                writer.writerow([distro, version, mod, pkg, arch, bid, used_url])
                csv_fh.flush()
                seen.add((distro, version, mod))
                log(f"    {mod} -> {bid}")


def main() -> int:
    inv = load_inventory()
    grouped = group_by_version(inv)
    log(f"Distinct (distro, version): {len(grouped)}")

    seen: set[tuple[str, str, str]] = set()
    mode = "a"
    write_header = not CSV_OUT.exists() or CSV_OUT.stat().st_size == 0
    if CSV_OUT.exists():
        with CSV_OUT.open() as f:
            r = csv.DictReader(f)
            for row in r:
                seen.add((row["distro"], row["version"], row["module"]))
        log(f"Resuming: {len(seen)} rows already in CSV")

    with CSV_OUT.open(mode, newline="") as csv_fh:
        writer = csv.writer(csv_fh)
        if write_header:
            writer.writerow(CSV_HEADER)
            csv_fh.flush()
        for (distro, version), modules in sorted(grouped.items()):
            try:
                process_version(distro, version, modules, writer, csv_fh, seen)
            except KeyboardInterrupt:
                raise
            except Exception as e:
                log(f"  fatal for {distro}/{version}: {e!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
