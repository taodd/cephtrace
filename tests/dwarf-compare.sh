#!/bin/bash

# This test is meant to be run after building osdtrace and radostrace.
# This generates new dwarf files and compares to the respective
# reference dwarf files in the repository.

set -ex

# Pull a set of dbgsym .ddebs straight from the Launchpad build artefact
# storage for the currently installed ceph source-package version, then
# install them with dpkg -i.  Used as a fallback when ddebs.ubuntu.com
# does not (yet) carry a matching dbgsym for the version on archive.
install_dbgsyms_from_launchpad() {
    local pkgs="$*"
    local ceph_ver arch src_page candidate_paths base_url workdir pkg
    ceph_ver=$(dpkg -l ceph-common | awk '/^ii/ {print $3}')
    arch=$(dpkg --print-architecture)
    src_page="https://launchpad.net/ubuntu/+source/ceph/${ceph_ver}"

    # The source-package page links one build per architecture.  We don't
    # know which build number is the amd64/arm64/... one without parsing
    # arch metadata out of the surrounding HTML, so instead enumerate the
    # build URLs and pick the first whose +files/ actually has a ddeb at
    # our arch — that proves it is the right build.
    candidate_paths=$(curl -fsSL "$src_page" \
                      | grep -oE '/[^"]+/\+build/[0-9]+' \
                      | sort -u)
    base_url=""
    for path in $candidate_paths; do
        local probe="https://launchpad.net${path}/+files/ceph-osd-dbgsym_${ceph_ver}_${arch}.ddeb"
        if curl -fsI -o /dev/null "$probe"; then
            base_url="https://launchpad.net${path}/+files"
            break
        fi
    done

    if [ -z "$base_url" ]; then
        echo "ERROR: no Launchpad build of ceph ${ceph_ver} on ${arch} carries the requested dbgsyms" >&2
        return 1
    fi

    echo "Fetching dbgsyms from $base_url"
    workdir=$(mktemp -d)
    pushd "$workdir" >/dev/null
    for pkg in $pkgs; do
        wget --no-verbose "${base_url}/${pkg}_${ceph_ver}_${arch}.ddeb"
    done

    # The .ddebs pin the matching main packages by exact version.  The CI
    # runner only has ceph-common installed up to this point — the apt
    # path would have pulled ceph-osd in transitively, but `dpkg -i` does
    # not resolve dependencies, so ensure every main package whose dbgsym
    # we're about to install is present first.
    #
    # Derive the main package name by stripping the "-dbgsym" suffix.
    local main_pkgs=""
    for pkg in $pkgs; do
        main_pkgs="$main_pkgs ${pkg%-dbgsym}"
    done
    # shellcheck disable=SC2086  # word-splitting on $main_pkgs is intended
    sudo apt install -y $main_pkgs

    sudo dpkg -i ./*.ddeb
    popd >/dev/null
    rm -rf "$workdir"
}

# Install the ceph package
sudo apt update
sudo apt install ceph-common -y

# Install debug symbols, needed to generate dwarf.json
sudo apt install ubuntu-dbgsym-keyring -y

echo "Types: deb
URIs: http://ddebs.ubuntu.com/
Suites: $(lsb_release -cs) $(lsb_release -cs)-updates
Components: main restricted universe multiverse
Signed-by: /usr/share/keyrings/ubuntu-dbgsym-keyring.gpg" | \
sudo tee -a /etc/apt/sources.list.d/ddebs.sources

sudo apt update

# Try to install dbgsyms via ddebs.ubuntu.com first.  Ubuntu's *-dbgsym
# packages carry a Depends: <main-pkg> (= <exact-version>) clause, so apt
# refuses the install whenever the matching version is missing from
# ddebs.ubuntu.com.  This is recurringly the case for SRU/security updates:
# the main packages reach archive.ubuntu.com noble-updates / noble-security
# weeks before the ddebs publication step runs, and on some uploads the
# ddebs aren't promoted at all (the .ddebs only ever exist inside the
# security-staging PPA build artefacts on Launchpad).  When that happens,
# fall back to fetching the .ddebs straight from the originating Launchpad
# build's +files/ directory.
DBGSYM_PKGS="ceph-osd-dbgsym librados2-dbgsym librbd1-dbgsym"
if sudo apt install -y $DBGSYM_PKGS; then
    echo "Installed dbgsyms from ddebs.ubuntu.com"
else
    echo "ddebs.ubuntu.com lacks a matching dbgsym version; falling back to Launchpad"
    install_dbgsyms_from_launchpad $DBGSYM_PKGS
fi

# Select the reference DWARF JSON by the ELF build-id embedded in the freshly
# generated JSON, NOT the package version.  The amd64 and amd64v3 builds of the
# same Ceph version (Ubuntu 26.04 publishes an amd64v3 package variant) share a
# version string but have distinct build-ids and distinct function addresses,
# so version-keying could pick the wrong-arch reference.  Build-id keying picks
# the correct file automatically, whichever variant the runner installed, and
# the caller prints exactly which file was matched.
find_ref_by_buildid() {
    local dir="$1" module="$2" generated="$3"
    python3 - "$dir" "$module" "$generated" <<'PY'
import glob, json, os, sys
ref_dir, module, generated = sys.argv[1:4]
want = json.load(open(generated)).get(module, {}).get("build_id")
if not want:
    sys.stderr.write(
        f"ERROR: generated JSON {generated} has no build_id for module {module}\n")
    sys.exit(1)
for path in sorted(glob.glob(os.path.join(ref_dir, "*_dwarf.json"))):
    try:
        d = json.load(open(path))
    except (OSError, ValueError):
        continue
    if d.get(module, {}).get("build_id") == want:
        print(path)
        sys.exit(0)
sys.stderr.write(
    f"ERROR: no reference DWARF JSON in {ref_dir} matches the installed "
    f"{module} build-id {want}; a reference file for this exact build is "
    f"probably missing and should be generated and checked in\n")
sys.exit(1)
PY
}

# Test osdtrace dwarf json generation
echo "Testing osdtrace dwarf json generation..."
osd_new_dwarf="generated-osd-dwarf.json"
./osdtrace -j $osd_new_dwarf
osd_ref_file=$(find_ref_by_buildid ./files/ubuntu/osdtrace ceph-osd "$osd_new_dwarf") \
    || { echo "osdtrace reference lookup failed"; exit 1; }
echo "Using reference DWARF JSON (matched by ceph-osd build-id): $osd_ref_file"
./tests/compare_dwarf_json.py "$osd_ref_file" "$osd_new_dwarf"
echo "osdtrace dwarf json comparison passed!"

# Test radostrace dwarf json generation
echo "Testing radostrace dwarf json generation..."
rados_new_dwarf="generated-rados-dwarf.json"
./radostrace -j $rados_new_dwarf
rados_ref_file=$(find_ref_by_buildid ./files/ubuntu/radostrace libceph-common.so.2 "$rados_new_dwarf") \
    || { echo "radostrace reference lookup failed"; exit 1; }
echo "Using reference DWARF JSON (matched by libceph-common.so.2 build-id): $rados_ref_file"
./tests/compare_dwarf_json.py "$rados_ref_file" "$rados_new_dwarf"
echo "radostrace dwarf json comparison passed!"

echo "All dwarf json comparisons passed successfully!"
