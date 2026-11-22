#!/usr/bin/env python3
"""Detect Ceph point releases for which we don't yet ship embedded DWARF JSONs.

Phase 1: centos-stream (el9 for quincy..tentacle, el10 for umbrella).  Probes
download.ceph.com for the ceph-osd RPMs of each (major.2.patch) candidate
version and diffs against the JSONs already present under
files/centos-stream/{osdtrace,radostrace}/.

Output (one row per (version, missing-tool-list)) is TSV on stdout so the
companion shell driver can read it line-by-line:

  centos-stream  osdtrace,radostrace  17.2.4  2:17.2.4-0.el9  <rpm-url>

The columns are: distro, comma-joined-tool-list, upstream-version,
package-version-string (matches what `osdtrace -j` records as the JSON's
`version` field), and the RPM URL the row's existence was inferred from
(included for traceability / debuggability of CI runs).
"""

from __future__ import annotations

import argparse
import sys
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CENTOS_DIR = REPO_ROOT / "files" / "centos-stream"
DOWNLOAD_BASE = "https://download.ceph.com"

# Map each modern Ceph major (quincy, reef, squid, tentacle, umbrella) to the
# EL release shipped by its upstream quay.io/ceph/ceph container image.
MAJOR_EL: dict[int, str] = {
    17: "el9",
    18: "el9",
    19: "el9",
    20: "el9",
    21: "el10",
}

# Centos-stream ceph-osd RPM URL template.
RPM_URL_TMPL = "{base}/rpm-{ver}/{el}/x86_64/ceph-osd-{ver}-0.{el}.x86_64.rpm"

# Probe up to this many patch releases per major.  20 is generous; quincy
# topped out at 17.2.9 and the longest historical Ceph line (octopus) ran
# through 15.2.17 so this leaves plenty of headroom.
CANDIDATE_PATCHES = list(range(0, 20))


def head(url: str, *, timeout: float = 15.0) -> int:
    """HTTP HEAD returning the status code, or 0 on network error.

    Used to probe whether a given RPM URL exists; HEAD is much cheaper than
    GET and download.ceph.com supports it.  A 0 return means we treat the
    URL as unavailable -- safer than retrying the workflow with a partial
    discovery on a flaky run.
    """
    req = urllib.request.Request(url, method="HEAD")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status
    except OSError:
        return 0


def upstream_rpm_versions() -> list[tuple[str, str]]:
    """Versions that have a matching ceph-osd RPM published upstream.

    Probes every (major.2.0 .. major.2.19) combination against each major's
    target EL release; cheap (~100 HEAD requests, ~10 s total) and avoids
    fragile HTML scraping of the directory index.  Returns a sorted
    (version-tuple-ascending) list of (version, el) pairs.
    """
    out: list[tuple[str, str]] = []
    for maj, el in MAJOR_EL.items():
        for patch in CANDIDATE_PATCHES:
            ver = f"{maj}.2.{patch}"
            url = RPM_URL_TMPL.format(base=DOWNLOAD_BASE, ver=ver, el=el)
            if head(url) == 200:
                out.append((ver, el))
    return out


def existing_versions(tool: str) -> set[tuple[str, str]]:
    """Return (version, el) pairs covered under files/centos-stream/<tool>/."""
    d = CENTOS_DIR / tool
    if not d.is_dir():
        return set()
    prefix = {"osdtrace": "osd-2:", "radostrace": "rados-2:"}[tool]
    found: set[tuple[str, str]] = set()
    for path in d.iterdir():
        name = path.name
        if not name.startswith(prefix) or not name.endswith("_dwarf.json"):
            continue
        stem = name[len(prefix):-len("_dwarf.json")]
        if "-0." not in stem:
            continue
        ver, el = stem.rsplit("-0.", 1)
        found.add((ver, el))
    return found


def version_key(v: str) -> tuple[int, ...]:
    """Sort key turning a dotted version string into an int tuple."""
    return tuple(int(x) for x in v.split("."))


def covered_ceiling(
    osd_have: set[tuple[str, str]], rados_have: set[tuple[str, str]]
) -> dict[int, int]:
    """Highest *fully covered* patch (both tools present) per major.

    "Fully covered" = a version we ship JSONs for in BOTH osdtrace and
    radostrace for its major's target EL release.  A major absent from the
    result has no fully-covered version at all (a brand-new line, or one
    we've never backfilled).
    """
    ceiling: dict[int, int] = {}
    for ver, el in osd_have & rados_have:
        try:
            major, _minor, patch = (int(x) for x in ver.split("."))
        except ValueError:
            continue
        if MAJOR_EL.get(major) != el:
            continue
        ceiling[major] = max(ceiling.get(major, -1), patch)
    return ceiling


def is_new_release(ver: str, ceiling: dict[int, int]) -> bool:
    """True when ver is a point release *newer* than our ceiling for its major,
    or belongs to a brand-new major line above our highest covered major.

    Used by --new-only to pick up freshly-published point releases and newly
    shipped major lines while leaving historical gaps on older majors to the
    backfill workflow.
    """
    major, _minor, patch = (int(x) for x in ver.split("."))
    if major in ceiling:
        return patch > ceiling[major]
    return bool(ceiling) and major > max(ceiling)


def main() -> None:
    """Probe upstream, diff against shipped JSONs, print missing TSV rows."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--new-only",
        action="store_true",
        help="emit only point releases newer than the highest fully-covered "
             "patch of each major (skip historical gaps on older lines)",
    )
    args = parser.parse_args()

    upstream = upstream_rpm_versions()
    if not upstream:
        # Treat a fully-empty probe set as a hard error: it almost always
        # means download.ceph.com is unreachable from the runner, and
        # opening a PR that deletes nothing is harmless but auto-merging
        # against an empty diff would be misleading.
        print("ERROR: no upstream RPMs detected; aborting", file=sys.stderr)
        sys.exit(1)

    osd_have = existing_versions("osdtrace")
    rados_have = existing_versions("radostrace")

    # --new-only: restrict to point releases above each major's fully-covered
    # ceiling (or brand-new majors above it), so the scheduled bot picks up
    # freshly-published releases and leaves historical gaps to backfill.
    ceiling = covered_ceiling(osd_have, rados_have) if args.new_only else {}

    # Group missing-tool sets by (version, el) so one container session can
    # generate both JSONs for the same version.
    missing: dict[tuple[str, str], list[str]] = {}
    for ver, el in upstream:
        if args.new_only and not is_new_release(ver, ceiling):
            continue
        tools: list[str] = []
        if (ver, el) not in osd_have:
            tools.append("osdtrace")
        if (ver, el) not in rados_have:
            tools.append("radostrace")
        if tools:
            missing[(ver, el)] = tools

    for ver, el in sorted(missing, key=lambda item: version_key(item[0])):
        tools = missing[(ver, el)]
        url = RPM_URL_TMPL.format(base=DOWNLOAD_BASE, ver=ver, el=el)
        print(
            "\t".join(
                [
                    "centos-stream",
                    ",".join(sorted(tools)),
                    ver,
                    f"2:{ver}-0.{el}",
                    url,
                ]
            )
        )


if __name__ == "__main__":
    main()
