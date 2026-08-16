#!/bin/bash
# Generate embedded-DWARF JSON(s) for a specific (distro, version) of Ceph
# using a disposable podman container.
#
# Usage:
#   gen_dwarf_for_version.sh <distro> <tools> <version> <pkgver>
#
#   distro:  centos-stream     (only one supported in Phase 1)
#   tools:   comma-separated, subset of {osdtrace,radostrace}
#   version: e.g. 17.2.4                  -- the upstream RPM version
#   pkgver:  e.g. 2:17.2.4-0.el9          -- recorded in JSON "version" field
#
# Side-effect: writes the JSON(s) under files/<distro>/<tool>/ in the repo
# (the repo is bind-mounted into the container, so the writes appear on
# the host immediately and the caller's `git status` shows them).
#
# The hard part of running `osdtrace -j` / `radostrace -j` is that both
# tools require a live PID whose /proc/<pid>/exe resolves to ceph-osd
# (so the DWARF parser can open the on-disk binary).  In a no-cluster
# container we have no naturally-running ceph-osd; we synthesise one by
# starting ceph-osd under gdb with `starti`, which stops the inferior at
# the first user-space instruction (after ld.so has loaded shared libs
# but before main runs).  /proc/<pid>/exe is then valid and stable for
# the lifetime of the gdb session, which we keep alive with a `shell`
# infinite-sleep command.

set -euo pipefail

usage() { echo "usage: $0 <distro> <tools> <version> <pkgver>" >&2; exit 2; }

[ $# -eq 4 ] || usage
DISTRO=$1
TOOLS=$2
VERSION=$3
PKGVER=$4

case "$PKGVER" in
    *.el8) EL=8; BUILD_REPO=PowerTools ;;
    *.el9) EL=9; BUILD_REPO=crb ;;
    *) echo "ERROR: unsupported package release in $PKGVER" >&2; exit 2 ;;
esac

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

case "$DISTRO" in
    centos-stream) ;;
    *) echo "ERROR: unsupported distro $DISTRO (only centos-stream in phase 1)" >&2; exit 2 ;;
esac

CTR_NAME_CLEAN=$(echo "$VERSION" | tr -c 'a-zA-Z0-9_.-' '_')
CTR="dwarfgen-${CTR_NAME_CLEAN}-$$"
cleanup() { podman rm -f "$CTR" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "==> generating DWARF for centos-stream ${VERSION} (tools: ${TOOLS})"

# Run as container root (the rootless-podman default): dnf/rpm below
# require superuser inside the container.  With rootless podman, container
# UID 0 maps back to the invoking host user's UID, so files written to the
# bind-mounted files/ are owned by the host user on the way out -- no
# chown needed and `git status` picks them up directly.  (Do NOT use
# --userns=keep-id here: it maps the container process to the host's
# non-root UID, which makes dnf fail with "must be run as superuser".)
# --privileged isn't needed: we don't manipulate the BPF subsystem from
# inside the container.
podman run -d --rm --name="$CTR" \
    -v "$REPO_ROOT":/workspace:Z \
    --workdir /workspace \
    "quay.io/centos/centos:stream${EL}" sleep infinity >/dev/null

if [ "$EL" = 8 ]; then
    # CentOS Stream 8 is retired, so its mirrorlist no longer resolves.  The
    # final package set is retained in the official vault.
    podman exec -u root "$CTR" bash -ec '
        rm -f /etc/yum.repos.d/*.repo
        for repo in BaseOS AppStream PowerTools extras; do
            cat >> /etc/yum.repos.d/centos-stream-vault.repo <<EOF
[$repo]
name=CentOS Stream 8 $repo vault
baseurl=https://vault.centos.org/8-stream/$repo/\$basearch/os/
gpgcheck=0
enabled=1
EOF
        done
    '
fi

echo "==> installing build deps + ceph ${VERSION} + debuginfo"

# crb enables glibc-devel.i686 + clang.  The build needs gdb only for the
# starti trick below.  --allowerasing lets dnf swap the image's preinstalled
# curl-minimal for the full curl we request (they conflict otherwise).
podman exec -u root "$CTR" dnf install -y --enablerepo="$BUILD_REPO" --allowerasing \
    gcc gcc-c++ clang make \
    elfutils-libelf-devel elfutils-devel \
    glibc-devel glibc-devel.i686 \
    python3 openssl-devel \
    gdb curl which >/dev/null

# Install ceph-osd + the three core libraries plus every matching debuginfo
# subpackage, WITH full dependency resolution.  A plain `rpm -ivh` can't pull
# in the dozens of runtime deps (ceph-base, libaio, thrift, tcmalloc,
# python3-rados, ...) that ceph-osd needs to even reach its entry point under
# gdb, so we point dnf at the pinned per-release ceph repo -- which carries
# both the regular and the -debuginfo/-debugsource RPMs -- and let it resolve
# the closure.  EPEL supplies thrift / lttng-ust / libpmemobj.  ceph-debuginfo
# + ceph-debugsource carry the inlined-frame info that osdtrace's DWARF walker
# needs even when the symbol it's resolving is in a per-binary -debuginfo
# package.
podman exec -u root "$CTR" dnf install -y epel-release >/dev/null

podman exec -i -u root "$CTR" \
    bash -c 'cat > /etc/yum.repos.d/ceph-pinned.repo' <<EOF
[ceph-pinned]
name=ceph-pinned-${VERSION}-x86_64
baseurl=https://download.ceph.com/rpm-${VERSION}/el${EL}/x86_64/
gpgcheck=0
enabled=1
[ceph-pinned-noarch]
name=ceph-pinned-${VERSION}-noarch
baseurl=https://download.ceph.com/rpm-${VERSION}/el${EL}/noarch/
gpgcheck=0
enabled=1
EOF

podman exec -u root "$CTR" dnf install -y --enablerepo="$BUILD_REPO" \
    ceph-osd ceph-common librbd1 librados2 \
    ceph-osd-debuginfo ceph-common-debuginfo \
    librbd1-debuginfo librados2-debuginfo \
    ceph-debuginfo ceph-debugsource >/dev/null

echo "==> building cephtrace inside the container"

# Always start from a clean .output so the previous host build's libbpf.a
# (compiled against a newer glibc, with __isoc23_strtoull etc.) doesn't
# pollute the el9 link.  This is the same trap we hit during the manual
# 17.2.8 / 17.2.9 prep work for PR #106.
podman exec --workdir=/workspace "$CTR" bash -ec '
    rm -rf .output
    make -j"$(nproc)" osdtrace radostrace >/dev/null
'

echo "==> starting holder process (gdb starti on ceph-osd --version)"

# starti starts ceph-osd, ld.so loads shared libraries, control transfers
# to the entry point (_start), gdb stops the inferior there.  None of
# ceph-osd's own initialisers run, so the process is harmless to hold
# indefinitely.  The trailing `shell` command keeps gdb attached.
podman exec "$CTR" bash -ec '
    rm -f /tmp/osd_holder.pid /tmp/gdb.pid
    nohup gdb -nx -batch-silent \
        -ex "set follow-fork-mode parent" \
        -ex "set pagination off" \
        -ex "starti" \
        -ex "shell echo \$\$ > /tmp/osd_holder.pid; while true; do sleep 60; done" \
        --args /usr/bin/ceph-osd --version >/tmp/gdb.log 2>&1 &
    echo $! > /tmp/gdb.pid
    # osd_holder.pid is written by the gdb shell command, which only runs
    # after starti -- its presence signals ceph-osd is stopped at its entry
    # point and ready to be inspected.
    for i in $(seq 1 60); do
        [ -s /tmp/osd_holder.pid ] && break
        sleep 0.5
    done
'

# ceph-osd (the gdb inferior) and the keep-alive shell command are *both*
# children of gdb, so locate ceph-osd via the gdb PID -- not via the holder
# shell's PID, which would only match that shell's own children.
OSD_PID=$(podman exec "$CTR" bash -ec '
    GDB=$(cat /tmp/gdb.pid 2>/dev/null || true)
    [ -n "$GDB" ] || { echo "gdb did not start" >&2; cat /tmp/gdb.log >&2; exit 1; }
    OSD=$(pgrep -P "$GDB" -x ceph-osd || true)
    [ -n "$OSD" ] || { echo "ceph-osd subprocess not found" >&2; ps -ef >&2; exit 1; }
    echo "$OSD"
')

echo "    ceph-osd holder PID: $OSD_PID"

for tool in ${TOOLS//,/ }; do
    case "$tool" in
        osdtrace)
            out="files/centos-stream/osdtrace/osd-${PKGVER}_dwarf.json"
            ;;
        radostrace)
            # radostrace's DWARF parse target is librados/librbd/libceph-
            # common.  It resolves library paths via /proc/<pid>/root (a
            # chroot-based filesystem walk), not via /proc/<pid>/maps -- so
            # the holder process doesn't need to have those libraries
            # *loaded*; it just needs them installed in the same mount
            # namespace, which the dnf install above guarantees.
            out="files/centos-stream/radostrace/rados-${PKGVER}_dwarf.json"
            ;;
        *)
            echo "ERROR: unknown tool $tool" >&2
            exit 2
            ;;
    esac
    echo "==> generating ${tool} JSON -> ${out}"
    podman exec --workdir=/workspace "$CTR" \
        ./"$tool" -j "$out" -p "$OSD_PID" >/tmp/${tool}-${VERSION}.log 2>&1 || {
            echo "ERROR: ${tool} -j failed; last 20 lines of /tmp/${tool}-${VERSION}.log:" >&2
            tail -20 /tmp/${tool}-${VERSION}.log >&2 || true
            exit 1
        }
    # Sanity: file exists and is non-trivial JSON.
    if ! [ -s "$REPO_ROOT/$out" ]; then
        echo "ERROR: $out was not written" >&2
        exit 1
    fi
done

echo "==> done: DWARF JSON(s) for ${VERSION} written under files/centos-stream/"
