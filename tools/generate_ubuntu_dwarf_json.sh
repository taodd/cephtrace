#!/bin/bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: tools/generate_ubuntu_dwarf_json.sh [options]

Generate Ubuntu DWARF JSON files for the installed or requested Ceph version.

Options:
  --ubuntu <version>              Ubuntu version label for logging
  --ceph-version <version>        Exact Ceph package version to install
  --launchpad-files-url <url>     Optional Launchpad +files URL fallback
  -h, --help                      Show this help
EOF
}

UBUNTU_VERSION=""
CEPH_VERSION=""
LAUNCHPAD_FILES_URL=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ubuntu)
            [[ $# -ge 2 ]] || { echo "--ubuntu requires a value" >&2; exit 1; }
            UBUNTU_VERSION="$2"
            shift 2
            ;;
        --ceph-version)
            [[ $# -ge 2 ]] || { echo "--ceph-version requires a value" >&2; exit 1; }
            CEPH_VERSION="$2"
            shift 2
            ;;
        --launchpad-files-url)
            [[ $# -ge 2 ]] || { echo "--launchpad-files-url requires a value" >&2; exit 1; }
            LAUNCHPAD_FILES_URL="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

if [[ -n "$UBUNTU_VERSION" ]]; then
    echo "Generating DWARF JSON files on Ubuntu $UBUNTU_VERSION"
fi

if [[ -n "$CEPH_VERSION" ]]; then
    echo "Requested exact Ceph version: $CEPH_VERSION"
else
    echo "Requested latest Ceph version from configured Ubuntu repositories"
fi

if [[ $(id -u) -eq 0 ]]; then
    SUDO=()
else
    SUDO=(sudo)
fi

export DEBIAN_FRONTEND=noninteractive

apt_install() {
    "${SUDO[@]}" apt-get install -y --no-install-recommends "$@"
}

apt_update() {
    "${SUDO[@]}" apt-get update
}

ubuntu_codename() {
    . /etc/os-release
    printf '%s\n' "$VERSION_CODENAME"
}

dpkg_arch() {
    dpkg --print-architecture
}

install_base_dependencies() {
    apt_update
    apt_install \
        ca-certificates \
        clang \
        curl \
        g++ \
        git \
        libc6-dev-i386 \
        libdw-dev \
        libelf-dev \
        make \
        python3 \
        wget \
        xz-utils \
        zstd
}

configure_ddeb_repository() {
    local codename sources_file
    codename=$(ubuntu_codename)
    sources_file="/etc/apt/sources.list.d/ddebs.sources"

    apt_install ubuntu-dbgsym-keyring

    if [[ ! -f "$sources_file" ]]; then
        "${SUDO[@]}" tee "$sources_file" >/dev/null <<EOF
Types: deb
URIs: http://ddebs.ubuntu.com/
Suites: $codename $codename-updates
Components: main restricted universe multiverse
Signed-by: /usr/share/keyrings/ubuntu-dbgsym-keyring.gpg
EOF
    fi

    apt_update
}

launchpad_source_page() {
    local version="$1"
    printf 'https://launchpad.net/ubuntu/+source/ceph/%s\n' "$version"
}

discover_launchpad_files_url() {
    local version="$1"
    local arch src_page candidate_paths path probe

    arch=$(dpkg_arch)
    src_page=$(launchpad_source_page "$version")
    echo "Discovering Launchpad +files URL from $src_page" >&2

    candidate_paths=$(curl -fsSL "$src_page" \
        | grep -oE '/[^" ]+/\+build/[0-9]+' \
        | sort -u || true)

    for path in $candidate_paths; do
        probe="https://launchpad.net${path}/+files/ceph-osd-dbgsym_${version}_${arch}.ddeb"
        if curl -fsI -o /dev/null "$probe"; then
            printf 'https://launchpad.net%s/+files\n' "$path"
            return 0
        fi
    done

    echo "ERROR: no Launchpad build for ceph $version on $arch carries ceph-osd-dbgsym" >&2
    return 1
}

resolve_launchpad_files_url() {
    local version="$1"
    if [[ -n "$LAUNCHPAD_FILES_URL" ]]; then
        printf '%s\n' "$LAUNCHPAD_FILES_URL"
    else
        discover_launchpad_files_url "$version"
    fi
}

download_launchpad_urls() {
    local files_url="$1"
    local mode="$2"
    local workdir html

    workdir=$(mktemp -d)
    html=$(curl -fsSL "$files_url")

    pushd "$workdir" >/dev/null
    if [[ "$mode" == "all" ]]; then
        printf '%s\n' "$html" \
            | grep -Eo 'https://[a-zA-Z0-9./?=_:+%~-]*launchpad[^"<> ]+\.deb' \
            | sort -u > urls.txt || true
    else
        : > urls.txt
    fi

    printf '%s\n' "$html" \
        | grep -Eo 'https://[a-zA-Z0-9./?=_:+%~-]*launchpad[^"<> ]+\.ddeb' \
        | grep -E '/(ceph-osd|librados2|librbd1)-dbgsym_' \
        | sort -u >> urls.txt || true

    if [[ ! -s urls.txt ]]; then
        echo "ERROR: no downloadable package URLs found at $files_url" >&2
        popd >/dev/null
        rm -rf "$workdir"
        return 1
    fi

    wget --content-disposition --no-verbose -i urls.txt
    printf '%s\n' "$workdir"
    popd >/dev/null
}

install_all_from_launchpad() {
    local version="$1"
    local files_url workdir

    files_url=$(resolve_launchpad_files_url "$version")
    echo "Installing Ceph packages and dbgsyms from $files_url"
    workdir=$(download_launchpad_urls "$files_url" all)
    pushd "$workdir" >/dev/null
    apt_install ./*.deb ./*.ddeb
    popd >/dev/null
    rm -rf "$workdir"
}

install_dbgsyms_from_launchpad() {
    local version="$1"
    local files_url workdir

    files_url=$(resolve_launchpad_files_url "$version")
    echo "Installing Ceph dbgsyms from $files_url"
    workdir=$(download_launchpad_urls "$files_url" dbgsyms)
    pushd "$workdir" >/dev/null
    "${SUDO[@]}" dpkg -i ./*.ddeb
    popd >/dev/null
    rm -rf "$workdir"
}

install_ceph_packages() {
    if [[ -n "$CEPH_VERSION" ]]; then
        if apt_install \
            ceph-common="$CEPH_VERSION" \
            ceph-osd="$CEPH_VERSION" \
            librados2="$CEPH_VERSION" \
            librbd1="$CEPH_VERSION"; then
            echo "Installed exact Ceph packages from APT"
        else
            echo "APT could not install exact Ceph version; falling back to Launchpad"
            install_all_from_launchpad "$CEPH_VERSION"
        fi
    else
        apt_install ceph-common ceph-osd librados2 librbd1
    fi
}

install_debug_symbols() {
    local installed_version="$1"
    local dbgsyms=(ceph-osd-dbgsym librados2-dbgsym librbd1-dbgsym)

    configure_ddeb_repository

    if [[ -n "$CEPH_VERSION" ]]; then
        if apt_install \
            ceph-osd-dbgsym="$installed_version" \
            librados2-dbgsym="$installed_version" \
            librbd1-dbgsym="$installed_version"; then
            echo "Installed exact dbgsyms from ddebs.ubuntu.com"
            return 0
        fi
    else
        if apt_install "${dbgsyms[@]}"; then
            echo "Installed latest dbgsyms from ddebs.ubuntu.com"
            return 0
        fi
    fi

    echo "ddebs.ubuntu.com lacks matching dbgsyms; falling back to Launchpad"
    install_dbgsyms_from_launchpad "$installed_version"
}

installed_ceph_version() {
    dpkg-query -W -f='${Version}\n' ceph-osd
}

OSD_DWARF=""
RADOS_DWARF=""

set_dwarf_paths() {
    local version="$1"

    mkdir -p files/ubuntu/osdtrace files/ubuntu/radostrace
    OSD_DWARF="files/ubuntu/osdtrace/osd-${version}_dwarf.json"
    RADOS_DWARF="files/ubuntu/radostrace/${version}_dwarf.json"
}

both_dwarf_files_exist() {
    [[ -f "$OSD_DWARF" && -f "$RADOS_DWARF" ]]
}

build_tools() {
    make -j"$(nproc)" radostrace osdtrace
}

validate_json_files() {
    local version="$1"
    shift

    python3 - "$version" "$@" <<'PY'
import json
import sys
from pathlib import Path

version = sys.argv[1]
files = [Path(p) for p in sys.argv[2:]]

for path in files:
    if not path.exists() or path.stat().st_size == 0:
        raise SystemExit(f"{path} does not exist or is empty")
    with path.open(encoding="utf-8") as f:
        data = json.load(f)
    if data.get("version") != version:
        raise SystemExit(
            f"{path} version {data.get('version')!r} does not match {version!r}"
        )
    if not data.get("arch"):
        raise SystemExit(f"{path} does not contain an arch field")
    modules = [
        value for value in data.values()
        if isinstance(value, dict) and ("func2pc" in value or "func2vf" in value)
    ]
    if not modules:
        raise SystemExit(f"{path} does not contain DWARF module data")
PY
}

stage_artifacts() {
    local osd_file="$1"
    local rados_file="$2"
    local artifact_dir="dwarf-json-artifacts"

    rm -rf "$artifact_dir"
    mkdir -p "$artifact_dir/$(dirname "$osd_file")" "$artifact_dir/$(dirname "$rados_file")"
    cp "$osd_file" "$artifact_dir/$osd_file"
    cp "$rados_file" "$artifact_dir/$rados_file"
}

if [[ -n "$CEPH_VERSION" ]]; then
    set_dwarf_paths "$CEPH_VERSION"
    if both_dwarf_files_exist; then
        echo "Both DWARF JSON files already exist; skipping package install, build, and generation:"
        echo "  $OSD_DWARF"
        echo "  $RADOS_DWARF"
        stage_artifacts "$OSD_DWARF" "$RADOS_DWARF"
        exit 0
    fi
fi

install_base_dependencies
install_ceph_packages

INSTALLED_VERSION=$(installed_ceph_version)
echo "Installed ceph-osd version: $INSTALLED_VERSION"

if [[ -n "$CEPH_VERSION" && "$INSTALLED_VERSION" != "$CEPH_VERSION" ]]; then
    echo "ERROR: installed ceph-osd version $INSTALLED_VERSION does not match requested $CEPH_VERSION" >&2
    exit 1
fi

set_dwarf_paths "$INSTALLED_VERSION"

if both_dwarf_files_exist; then
    echo "Both DWARF JSON files already exist; skipping generation:"
    echo "  $OSD_DWARF"
    echo "  $RADOS_DWARF"
    stage_artifacts "$OSD_DWARF" "$RADOS_DWARF"
    exit 0
fi

install_debug_symbols "$INSTALLED_VERSION"
build_tools

GENERATED_FILES=()

if [[ -f "$OSD_DWARF" ]]; then
    echo "DWARF JSON file already exists; not overwriting: $OSD_DWARF"
else
    ./osdtrace -j "$OSD_DWARF"
    GENERATED_FILES+=("$OSD_DWARF")
fi

if [[ -f "$RADOS_DWARF" ]]; then
    echo "DWARF JSON file already exists; not overwriting: $RADOS_DWARF"
else
    ./radostrace -j "$RADOS_DWARF"
    GENERATED_FILES+=("$RADOS_DWARF")
fi

if [[ ${#GENERATED_FILES[@]} -gt 0 ]]; then
    validate_json_files "$INSTALLED_VERSION" "${GENERATED_FILES[@]}"
fi
stage_artifacts "$OSD_DWARF" "$RADOS_DWARF"

echo "Generated DWARF JSON files:"
echo "  $OSD_DWARF"
echo "  $RADOS_DWARF"
