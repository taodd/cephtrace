#!/bin/bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: tools/generate_ubuntu_dwarf_json.sh [options]

Generate Ubuntu DWARF JSON files for the installed or requested Ceph version.

Options:
  --ubuntu <version>              Ubuntu version label for logging
  --ceph-version <version>        Ceph version to install. x.y.z values use
                                  https://download.ceph.com/debian-x.y.z/;
                                  full distro package versions use Ubuntu APT.
  --launchpad-files-url <url>     Optional Launchpad +files URL fallback
  -h, --help                      Show this help
EOF
}

UBUNTU_VERSION=""
CEPH_VERSION=""
CEPH_PACKAGE_VERSION=""
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
    echo "Requested Ceph version: $CEPH_VERSION"
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
        gnupg \
        libc6-dev-i386 \
        libdw-dev \
        libelf-dev \
        libssl-dev \
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

is_upstream_ceph_version() {
    [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
}

expected_upstream_package_version() {
    local version="$1"
    local codename

    codename=$(ubuntu_codename)
    printf '%s-1%s\n' "$version" "$codename"
}

configure_ceph_repository() {
    local version="$1"
    local codename keyring sources_file

    codename=$(ubuntu_codename)
    keyring="/usr/share/keyrings/ceph.gpg"
    sources_file="/etc/apt/sources.list.d/ceph.sources"

    curl -fsSL https://download.ceph.com/keys/release.asc \
        | "${SUDO[@]}" gpg --dearmor --yes -o "$keyring"

    "${SUDO[@]}" tee "$sources_file" >/dev/null <<EOF
Types: deb
URIs: https://download.ceph.com/debian-$version/
Suites: $codename
Components: main
Signed-by: $keyring
EOF

    apt_update
}

resolve_ceph_package_version() {
    local requested="$1"

    python3 - "$requested" <<'PY'
import subprocess
import sys

requested = sys.argv[1]
try:
    output = subprocess.check_output(
        ["apt-cache", "madison", "ceph-osd"], text=True
    )
except subprocess.CalledProcessError as exc:
    raise SystemExit(exc.returncode)

versions = []
for line in output.splitlines():
    parts = [part.strip() for part in line.split("|")]
    if len(parts) >= 2:
        versions.append(parts[1])

if requested in versions:
    print(requested)
    raise SystemExit(0)

prefix = f"{requested}-"
matches = [version for version in versions if version.startswith(prefix)]
if matches:
    print(matches[0])
    raise SystemExit(0)

raise SystemExit(
    f"no ceph-osd package version matching {requested!r}; candidates: "
    + ", ".join(versions)
)
PY
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
        if is_upstream_ceph_version "$CEPH_VERSION"; then
            CEPH_PACKAGE_VERSION=$(resolve_ceph_package_version "$CEPH_VERSION")
            apt_install \
                ceph-common="$CEPH_PACKAGE_VERSION" \
                ceph-osd="$CEPH_PACKAGE_VERSION" \
                librados2="$CEPH_PACKAGE_VERSION" \
                librbd1="$CEPH_PACKAGE_VERSION"
            echo "Installed Ceph packages from download.ceph.com at $CEPH_PACKAGE_VERSION"
            return 0
        fi

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

    if [[ -n "$CEPH_VERSION" ]] && is_upstream_ceph_version "$CEPH_VERSION"; then
        apt_install \
            ceph-common-dbg="$installed_version" \
            ceph-osd-dbg="$installed_version" \
            librados2-dbg="$installed_version" \
            librbd1-dbg="$installed_version"
        echo "Installed Ceph debug packages from download.ceph.com"
        return 0
    fi

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
    if is_upstream_ceph_version "$CEPH_VERSION"; then
        set_dwarf_paths "$(expected_upstream_package_version "$CEPH_VERSION")"
    else
        set_dwarf_paths "$CEPH_VERSION"
    fi
    if both_dwarf_files_exist; then
        echo "Both DWARF JSON files already exist; skipping package install, build, and generation:"
        echo "  $OSD_DWARF"
        echo "  $RADOS_DWARF"
        stage_artifacts "$OSD_DWARF" "$RADOS_DWARF"
        exit 0
    fi
fi

install_base_dependencies

if [[ -n "$CEPH_VERSION" ]] && is_upstream_ceph_version "$CEPH_VERSION"; then
    configure_ceph_repository "$CEPH_VERSION"
fi

install_ceph_packages

INSTALLED_VERSION=$(installed_ceph_version)
echo "Installed ceph-osd version: $INSTALLED_VERSION"

if [[ -n "$CEPH_VERSION" ]]; then
    if is_upstream_ceph_version "$CEPH_VERSION"; then
        if [[ "$INSTALLED_VERSION" != "$CEPH_PACKAGE_VERSION" ]]; then
            echo "ERROR: installed ceph-osd version $INSTALLED_VERSION does not match requested $CEPH_PACKAGE_VERSION" >&2
            exit 1
        fi
    elif [[ "$INSTALLED_VERSION" != "$CEPH_VERSION" ]]; then
        echo "ERROR: installed ceph-osd version $INSTALLED_VERSION does not match requested $CEPH_VERSION" >&2
        exit 1
    fi
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
