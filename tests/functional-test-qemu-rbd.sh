#!/bin/bash

# Functional test: radostrace tracing a qemu VM backed by an RBD disk.
#
# This covers the "VM with an rbd device" scenario end to end:
#   - a cirros guest boots from rbd:<pool>/<image> through the *host* librbd
#     (qemu links the distro librbd, not the cluster's), and runs an in-guest
#     dd write + read workload driven over the serial console
#   - radostrace attaches to the qemu process with NO -i and NO
#     --skip-version-check, which exercises the two v1.6 code paths users
#     hit with VMs: embedded DWARF matched by the host librbd's ELF
#     build-id, and library path resolution from /proc/<pid>/maps
#
# Defaults assume the MicroCeph cluster set up by functional-test-microceph.sh
# (the CI job runs that first).  For a non-snap cluster set:
#   SKIP_CLUSTER_SETUP=1 CEPH_CMD=ceph RBD_CMD=rbd SKIP_CONF_EXPORT=1

set -e
# Run with `bash -x` for command-level tracing when debugging.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# shellcheck source=lib/log.sh
source "$SCRIPT_DIR/lib/log.sh"
# shellcheck source=lib/microceph-setup.sh
source "$SCRIPT_DIR/lib/microceph-setup.sh"
# shellcheck source=lib/verify-trace-output.sh
source "$SCRIPT_DIR/lib/verify-trace-output.sh"

CEPH_CMD=${CEPH_CMD:-microceph.ceph}
RBD_CMD=${RBD_CMD:-microceph.rbd}
SKIP_CLUSTER_SETUP=${SKIP_CLUSTER_SETUP:-0}
SKIP_CONF_EXPORT=${SKIP_CONF_EXPORT:-0}
POOL=${POOL:-test_pool}
IMAGE=${IMAGE:-vmdisk}

RADOSTRACE_LOG=/tmp/radostrace-qemu.log
RADOSTRACE_ERR=/tmp/radostrace-qemu.err
CONSOLE_LOG=/tmp/qemu-console.log
CIRROS_IMG=${CIRROS_IMG:-/tmp/cirros-0.6.2-x86_64-disk.img}
# GitHub releases first: download.cirros-cloud.net regularly stalls from CI
# runners (a 9-minute hang before curl's exit 28 took down one run).
CIRROS_URLS=(
    "https://github.com/cirros-dev/cirros/releases/download/0.6.2/cirros-0.6.2-x86_64-disk.img"
    "https://download.cirros-cloud.net/0.6.2/cirros-0.6.2-x86_64-disk.img"
)

# Row thresholds.  A cirros boot + 32 MiB write + 80 MiB read produced
# 200-400 rows in validation runs across octopus..tentacle; require a
# conservative floor so the test fails loudly if tracing breaks.
MIN_TOTAL_ROWS=50
MIN_WRITE_ROWS=10
MIN_READ_ROWS=10

echo "=== qemu + RBD disk functional test for radostrace ==="
echo "Project root: $PROJECT_ROOT"

# The cirros image (and therefore qemu-system-x86_64) is x86_64-only.
if [ "$(uname -m)" != "x86_64" ]; then
    info "SKIP: test requires x86_64 (got $(uname -m))"
    exit 0
fi

cleanup() {
    info "=== Cleanup ==="
    pkill -f qemu-system-x86_64 || true
    pkill -f radostrace || true

    if [[ -e $RADOSTRACE_LOG ]]; then
        info "radostrace output (tail):"
        tail -50 $RADOSTRACE_LOG
        info " === END of radostrace output === "
    fi
    if [[ -e $RADOSTRACE_ERR ]]; then
        info "radostrace stderr (tail):"
        tail -20 $RADOSTRACE_ERR
        info " === END of radostrace stderr === "
    fi
    if [[ -e $CONSOLE_LOG ]]; then
        info "guest console (tail):"
        tail -30 $CONSOLE_LOG
        info " === END of guest console === "
    fi
}
trap cleanup EXIT

info "=== Step 1: Install qemu and expect ==="
export DEBIAN_FRONTEND=noninteractive
apt-get install -y -q qemu-system-x86 qemu-utils qemu-block-extra expect >/dev/null

info "=== Step 2: Ensure cluster is up ==="
if [ "$SKIP_CLUSTER_SETUP" != "1" ]; then
    microceph_setup_single_node
fi

if [ "$SKIP_CONF_EXPORT" != "1" ]; then
    # qemu/qemu-img run against the *host* librbd, which reads /etc/ceph.
    # Export microceph's conf + admin keyring so host clients can reach the
    # snap-confined cluster.
    info "Exporting microceph conf to /etc/ceph for the host librbd"
    mkdir -p /etc/ceph
    cp /var/snap/microceph/current/conf/ceph.conf /etc/ceph/ceph.conf
    cp /var/snap/microceph/current/conf/ceph.keyring \
        /etc/ceph/ceph.client.admin.keyring
fi

info "=== Step 3: Check embedded DWARF coverage for the host librbd ==="
LIBRBD_VER=$(dpkg-query -W -f='${Version}' librbd1)
info "Host librbd1 version: $LIBRBD_VER"
if ! "$PROJECT_ROOT/radostrace" --list-embedded | grep -qF "$LIBRBD_VER"; then
    err "radostrace has no embedded DWARF for host librbd $LIBRBD_VER."
    err "The embedded-DWARF refresh bot should add it; until then this"
    err "host's qemu VMs are not traceable without -i."
    exit 1
fi

info "=== Step 4: Create the RBD boot image ==="
if ! $CEPH_CMD osd pool ls | grep -q "^${POOL}$"; then
    $CEPH_CMD osd pool create "$POOL" 32
    $CEPH_CMD osd pool application enable "$POOL" rbd
fi
# layering-only (no object-map): reads of unallocated regions must reach
# RADOS or radostrace sees no read ops for them.
$RBD_CMD rm "$POOL/$IMAGE" 2>/dev/null || true
$RBD_CMD create --image-feature layering --size 1G "$POOL/$IMAGE"

if [ ! -s "$CIRROS_IMG" ]; then
    for url in "${CIRROS_URLS[@]}"; do
        info "Downloading cirros guest image from $url ..."
        if curl -fsSL --retry 3 --connect-timeout 15 --max-time 180 \
            -o "$CIRROS_IMG" "$url"; then
            break
        fi
        rm -f "$CIRROS_IMG"
    done
    if [ ! -s "$CIRROS_IMG" ]; then
        err "Could not download the cirros image from any mirror"
        exit 1
    fi
fi
# -n: write into the pre-created image, preserving its feature set
qemu-img convert -n -O raw "$CIRROS_IMG" "rbd:$POOL/$IMAGE"

info "=== Step 5: Boot the guest from the RBD disk ==="
ACCEL=tcg
[ -w /dev/kvm ] && ACCEL=kvm
info "Using qemu accelerator: $ACCEL"
# rbd_cache=false in the URI: cached reads never reach RADOS and would
# hide the read path from radostrace (same rationale as the bench test).
expect "$SCRIPT_DIR/lib/qemu-guest-io.exp" "$ACCEL" \
    "rbd:$POOL/$IMAGE:rbd_cache=false" >"$CONSOLE_LOG" 2>&1 &
EXPECT_PID=$!

# Discover the qemu process with radostrace --list, the same way a user
# would.  qemu maps libceph-common.so.2 (via librbd) as soon as it opens
# the rbd drive at startup, so it appears in --list before the guest even
# boots.  This also covers --list end to end: process discovery plus the
# Traceable column's embedded build-id resolution for the qemu row.
# Columns: PID  Container  Traceable  Ceph-Version  Executable-Path
QEMU_PID=""
QEMU_TRACEABLE=""
for _ in $(seq 1 60); do
    # `|| true`: read returns 1 on an empty poll (qemu not registered in
    # --list yet), which set -e would otherwise turn into a silent exit.
    read -r QEMU_PID QEMU_TRACEABLE < <("$PROJECT_ROOT/radostrace" --list 2>/dev/null \
        | awk '$5 ~ /qemu-system-x86_64$/ {print $1, $3; exit}') || true
    [ -n "$QEMU_PID" ] && break
    sleep 0.5
done
if [ -z "$QEMU_PID" ]; then
    err "radostrace --list did not report a qemu-system-x86_64 process"
    "$PROJECT_ROOT/radostrace" --list || true
    exit 1
fi
if [ "$QEMU_TRACEABLE" != "yes" ]; then
    err "radostrace --list reports qemu PID $QEMU_PID as Traceable=$QEMU_TRACEABLE"
    "$PROJECT_ROOT/radostrace" --list || true
    exit 1
fi
info "radostrace --list found qemu PID $QEMU_PID (Traceable=yes)"

info "=== Step 6: Trace the qemu process with radostrace ==="
# No -i, no --skip-version-check: embedded DWARF matched by build-id.
# The 600 s ceiling comfortably outlasts a TCG boot; the trace is stopped
# as soon as the guest powers off.
# stderr goes to its own file: tool log lines (e.g. "Caught signal 2" on
# our SIGINT) otherwise interleave mid-row with stdout in the shared file
# and the split fragments confuse the row parser.
timeout 600 "$PROJECT_ROOT/radostrace" -p "$QEMU_PID" \
    >"$RADOSTRACE_LOG" 2>"$RADOSTRACE_ERR" &
RADOSTRACE_BG=$!
sleep 3
if ! kill -0 $RADOSTRACE_BG 2>/dev/null; then
    err "radostrace exited prematurely"
    exit 1
fi

if ! wait $EXPECT_PID; then
    err "Guest session failed (boot/login/dd did not complete)"
    exit 1
fi
# Both I/O phases must have actually run inside the guest.
for marker in DD_WRITE_OK DD_READ_OK; do
    if ! grep -q $marker "$CONSOLE_LOG"; then
        err "Guest console is missing the $marker marker"
        exit 1
    fi
done
info "Guest completed its write+read workload"

sleep 1
kill -INT $RADOSTRACE_BG 2>/dev/null || true
wait $RADOSTRACE_BG 2>/dev/null || true

info "=== Step 7: Verify radostrace output ==="
# `osd pool ls detail` quotes the pool name: pool 3 'rbd' replicated ...
POOL_ID=$($CEPH_CMD osd pool ls detail | awk -v p="'$POOL'" '$1 == "pool" && $3 == p {print $2}')
info "Pool $POOL has id ${POOL_ID:-unknown}"

total=0; writes=0; reads=0; rbd_data_rows=0; bad_pool=0; malformed=0
while IFS='|' read -r pid _client _tid pool _pg _acting wr _size _latency _complete object; do
    [ -z "$pid" ] && continue
    # Reject fragments that slipped past the loose row filter (e.g. a row
    # split by an interleaved log line, or cut by an unclean kill): a real
    # row always has W/R in the wr column and a numeric pool id.
    case "$wr" in
        W|R) ;;
        *) malformed=$((malformed + 1)); continue ;;
    esac
    case "$pool" in
        ''|*[!0-9]*) malformed=$((malformed + 1)); continue ;;
    esac
    total=$((total + 1))
    case "$wr" in
        W) writes=$((writes + 1)) ;;
        R) reads=$((reads + 1)) ;;
    esac
    case "$object" in rbd_data.*) rbd_data_rows=$((rbd_data_rows + 1));; esac
    if [ -n "$POOL_ID" ] && [ "$pool" != "$POOL_ID" ]; then
        bad_pool=$((bad_pool + 1))
    fi
done < <(_radostrace_rows "$RADOSTRACE_LOG")

info "radostrace captured: total=$total writes=$writes reads=$reads rbd_data_rows=$rbd_data_rows bad_pool=$bad_pool malformed=$malformed"

fail=0
if [ "$total" -lt "$MIN_TOTAL_ROWS" ]; then
    err "Too few rows: $total < $MIN_TOTAL_ROWS"
    fail=1
fi
if [ "$writes" -lt "$MIN_WRITE_ROWS" ]; then
    err "Too few write rows: $writes < $MIN_WRITE_ROWS"
    fail=1
fi
if [ "$reads" -lt "$MIN_READ_ROWS" ]; then
    err "Too few read rows: $reads < $MIN_READ_ROWS (rbd cache short-circuit?)"
    fail=1
fi
if [ "$rbd_data_rows" -lt "$MIN_TOTAL_ROWS" ]; then
    err "Too few rbd_data object rows: $rbd_data_rows"
    fail=1
fi
if [ "$bad_pool" -gt 0 ]; then
    err "$bad_pool rows targeted a pool other than $POOL (id $POOL_ID)"
    fail=1
fi
# A couple of malformed fragments can result from stopping the tool
# mid-write; more than that points at an output-format regression.
if [ "$malformed" -gt 5 ]; then
    err "$malformed malformed rows (output format regression?)"
    fail=1
fi
[ "$fail" -eq 0 ] || exit 1

info "✓ radostrace traced the qemu VM's RBD I/O successfully"
echo "=== qemu + RBD disk functional test PASSED ==="
