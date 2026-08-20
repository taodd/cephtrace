#!/bin/bash

# Functional test for osdtrace and radostrace with MicroCeph
# This test deploys a single-node MicroCeph cluster and verifies that
# osdtrace and radostrace can successfully trace Ceph operations

set -e  # Exit on error
# Run with `bash -x ./tests/functional-test-microceph.sh` for command-level
# tracing if you need to debug.  Enabling set -x unconditionally drowns the
# CI log with per-loop trace lines from the verifier.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# shellcheck source=lib/log.sh
source "$SCRIPT_DIR/lib/log.sh"
# shellcheck source=lib/microceph-setup.sh
source "$SCRIPT_DIR/lib/microceph-setup.sh"
# shellcheck source=lib/verify-trace-output.sh
source "$SCRIPT_DIR/lib/verify-trace-output.sh"
# shellcheck source=lib/verify-list-output.sh
source "$SCRIPT_DIR/lib/verify-list-output.sh"

echo "=== MicroCeph Functional Test for osdtrace and radostrace ==="
echo "Project root: $PROJECT_ROOT"

OSDTRACE_LOG="/tmp/osdtrace.log"
OSDTRACE_ID_LOG="/tmp/osdtrace-id.log"
RADOSTRACE_LOG="/tmp/radostrace.log"

# OSD id targeted by the --id-based osdtrace run.  Must differ from the OSD
# the -p-based run attaches to (osd.1) so the two runs exercise distinct
# ceph-osd PIDs; microceph creates osd.0/osd.1/osd.2 in this test's setup.
TARGET_OSD_ID=2

# Cleanup function
cleanup() {
    info "=== Cleanup ==="
    # Kill any running trace processes
    pkill -f osdtrace || true
    pkill -f radostrace || true
    pkill -f "rbd bench" || true

    # The hung-op scenario freezes OSDs. Always restore them, including when a
    # later assertion fails.
    kill -CONT $(pgrep -f "ceph-osd") 2>/dev/null || true

    if [[ -e $OSDTRACE_LOG ]]; then
        info "OSD trace output:"
        cat $OSDTRACE_LOG
        info " === END of OSD trace === "
    fi

    if [[ -e $OSDTRACE_ID_LOG ]]; then
        info "OSD trace (--id $TARGET_OSD_ID) output:"
        cat $OSDTRACE_ID_LOG
        info " === END of OSD trace (--id) === "
    fi

    if [[ -e $RADOSTRACE_LOG ]]; then
        info "RADOS trace output:"
        cat $RADOSTRACE_LOG
        info " === END of RADOS trace === "
    fi

    # Remove test files
    rm -f $OSDTRACE_LOG $OSDTRACE_ID_LOG $RADOSTRACE_LOG

    # Remove test RBD resources
    microceph.rbd rm test_pool/testimage 2>/dev/null || true
    microceph.ceph osd pool delete test_pool test_pool --yes-i-really-really-mean-it 2>/dev/null || true

    info "Cleanup completed"
}

trap cleanup EXIT

# Check if running as root or with sudo
if [ "$EUID" -ne 0 ]; then
    err "This test must be run as root or with sudo"
    exit 1
fi

# Check if osdtrace and radostrace binaries exist
if [ ! -f "$PROJECT_ROOT/osdtrace" ]; then
    err "osdtrace binary not found at $PROJECT_ROOT/osdtrace"
    err "Please build the project first with 'make osdtrace'"
    exit 1
fi

if [ ! -f "$PROJECT_ROOT/radostrace" ]; then
    err "radostrace binary not found at $PROJECT_ROOT/radostrace"
    err "Please build the project first with 'make radostrace'"
    exit 1
fi

info "=== Step 1: Setup MicroCeph (install + bootstrap + OSDs + wait healthy) ==="
if ! microceph_setup_single_node 3 3G 120; then
    err "MicroCeph cluster did not become healthy within timeout"
    exit 1
fi

# Disable librbd cache in microceph's snap conf so reads always reach
# RADOS (otherwise radostrace would never see the read path).
if ! microceph_disable_rbd_cache; then
    err "Failed to disable rbd_cache in microceph's snap conf"
    exit 1
fi

microceph.ceph status
microceph --version

echo "=== Step 2: Get Ceph version from snap metadata ==="
# Primary: read from snap's metadata.yaml
CEPH_VERSION=$(grep '^ceph-version:' /snap/microceph/current/share/metadata.yaml 2>/dev/null | awk '{print $2}')

# Fallback: parse from snap's manifest.yaml
if [ -z "$CEPH_VERSION" ]; then
    CEPH_VERSION=$(grep 'ceph-osd=' /snap/microceph/current/snap/manifest.yaml | sed 's/.*ceph-osd=//')
fi

info "Ceph version: $CEPH_VERSION"

info "=== Step 3: Locate DWARF JSON files in repository ==="
# Reference filenames may carry an optional architecture suffix
# (e.g. osd-19.2.3-0ubuntu0.24.04.3_arm64_dwarf.json) when multiple arches
# of the same package version are checked in.  Glob and pick the first match.
OSD_DWARF=$(ls "$PROJECT_ROOT/files/ubuntu/osdtrace/osd-${CEPH_VERSION}"*_dwarf.json 2>/dev/null | head -1)
RADOS_DWARF=$(ls "$PROJECT_ROOT/files/ubuntu/radostrace/${CEPH_VERSION}"*_dwarf.json 2>/dev/null | head -1)

if [ -z "$OSD_DWARF" ]; then
    info "OSD DWARF file not found for version ${CEPH_VERSION}"
    info "Looking for any available OSD DWARF files..."
    OSD_DWARF=$(find "$PROJECT_ROOT/files/ubuntu/osdtrace/" -name "*_dwarf.json" | head -1)
    if [ -z "$OSD_DWARF" ]; then
        err "No OSD DWARF files found in repository"
        exit 1
    fi
    info "Using: $OSD_DWARF"
fi

if [ -z "$RADOS_DWARF" ]; then
    info "Rados DWARF file not found for version ${CEPH_VERSION}"
    info "Looking for any available radostrace DWARF files..."
    RADOS_DWARF=$(find "$PROJECT_ROOT/files/ubuntu/radostrace/" -name "*_dwarf.json" | head -1)
    if [ -z "$RADOS_DWARF" ]; then
        err "No radostrace DWARF files found in repository"
        exit 1
    fi
    info "Using: $RADOS_DWARF"
fi

info "Using OSD DWARF file: $OSD_DWARF"
info "Using Rados DWARF file: $RADOS_DWARF"

info "=== Step 4: Find OSD process PID ==="
OSD_PID=$(pgrep -f "ceph-osd.*--id 1" | head -1)
if [ -z "$OSD_PID" ]; then
    err "Could not find ceph-osd process"
    ps aux | grep ceph-osd
    exit 1
fi
info "Found OSD process: PID $OSD_PID"

info "=== Step 4b: Verify osdtrace --list discovers the snap-confined OSDs ==="
# MicroCeph deploys 3 OSDs (see microceph_setup_single_node call above), each
# snap-confined.  --list must enumerate all three, mark them Container=yes
# (snap mount ns), resolve a non-"unknown" traceability verdict through the
# snap namespace, and - when traceable - report the snap's exact Ceph version.
verify_osdtrace_list_microceph "$PROJECT_ROOT/osdtrace" 3 "$CEPH_VERSION"

info "=== Step 5: Create RBD pool and image for testing ==="
if ! microceph.ceph osd pool ls | grep -q "^test_pool$"; then
    microceph.ceph osd pool create test_pool 32
    microceph.ceph osd pool application enable test_pool rbd
fi

# Recreate image fresh with only the `layering` feature: drops object-map,
# which would otherwise short-circuit reads of unallocated regions in the
# librbd client and hide read-path ops from radostrace.
microceph.rbd rm test_pool/testimage 2>/dev/null || true
microceph.rbd create --image-feature layering --size 1G test_pool/testimage

info "=== Step 6: Start osdtrace in background ==="
# Trace runtime is 30 s — outlasts the bench (20 s) with enough margin to
# stay attached for its entire lifetime even though osdtrace starts first.
timeout 30 $PROJECT_ROOT/osdtrace -i $OSD_DWARF -p $OSD_PID --skip-version-check >$OSDTRACE_LOG 2>&1 &
sleep 2 # ensure osdtrace starts before we get its PID
OSDTRACE_PID=$(pidof osdtrace)
info "Started osdtrace with PID $OSDTRACE_PID"
sleep 3

info "=== Step 6b: Start a second osdtrace targeting OSD $TARGET_OSD_ID via --id ==="
# Two osdtrace processes can attach uprobes to disjoint PIDs without
# interference (each owns its own BPF maps/ringbuf).  This run validates
# the --id resolver: it must enumerate ceph-osd processes, map OSD ID
# $TARGET_OSD_ID to its PID, and attach to *only* that PID — which the
# verifier then proves by checking that every captured row carries
# osd_id=$TARGET_OSD_ID (using verify_osdtrace_targets_only).
timeout 30 $PROJECT_ROOT/osdtrace -i $OSD_DWARF --id $TARGET_OSD_ID --skip-version-check >$OSDTRACE_ID_LOG 2>&1 &
OSDTRACE_ID_BG_PID=$!
sleep 3

info "=== Step 7: Generate I/O traffic via rbd bench ==="
# Random 2 MiB read-write mix via the snap-confined rbd bench — runs
# inside the microceph snap so it picks up the bundled librbd/librados
# that match our DWARF JSON (host-side tools load Ubuntu's apt librados,
# a different Ceph version, and the uprobe offsets would be wrong).
# Single thread + 2 MiB blocks keeps the captured-row count to a couple
# hundred over the 20 s run.
# `--io-total 100G` is way more than any 20 s run can do; `timeout 20`
# gives us a fixed runtime instead.
timeout 20 microceph.rbd bench \
    --io-type readwrite --rw-mix-read 50 \
    --io-pattern rand \
    --io-size 2M --io-threads 1 \
    --io-total 100G \
    test_pool/testimage &

info "=== Step 8: Start radostrace in background ==="
# microceph.rbd bench runs through a snap wrapper chain (snap-run →
# snap-confine → rbd).  We must find the PID of the actual rbd binary —
# the only process in that chain that has librados.so.2 mapped into its
# address space.  Poll /proc/<pid>/maps for each candidate.
RBD_ACTUAL_PID=""
for i in $(seq 1 60); do
    for pid in $(pgrep -f "rbd" 2>/dev/null); do
        if grep -q "librados" /proc/$pid/maps 2>/dev/null; then
            RBD_ACTUAL_PID=$pid
            break 2
        fi
    done
    sleep 0.5
done

if [ -z "$RBD_ACTUAL_PID" ]; then
    err "Could not find an rbd process with librados loaded in its maps"
    exit 1
fi
info "Attaching radostrace to rbd PID $RBD_ACTUAL_PID (confirmed librados-loaded)"

timeout 30 $PROJECT_ROOT/radostrace -p $RBD_ACTUAL_PID -i $RADOS_DWARF --skip-version-check >$RADOSTRACE_LOG 2>&1 &
sleep 2 # ensure radostrace starts before we get its PID
RADOSTRACE_PID=$(pidof radostrace)
info "Started radostrace with PID $RADOSTRACE_PID"

info "=== Step 8b: Verify radostrace --list while the snap client is live ==="
# The rbd bench client is snap-confined and only exists during the bench, so
# this check runs now (before the Step 9 wait).  --list must discover that
# client (Container=yes, libraries resolved under /snap/microceph/...) and
# also surface the snap ceph-mon/mgr/mds daemons, proving daemon discovery -
# not just the transient bench process.
verify_radostrace_list_microceph "$PROJECT_ROOT/radostrace" "$RBD_ACTUAL_PID" "$CEPH_VERSION"

info "=== Step 9: Wait for bench + traces to complete"
wait

info "=== Step 10: Gather cluster facts for verification ==="

# Resolve once and pass into the shared verifiers — they don't talk to ceph
# directly, so the test owns this lookup.
TEST_POOL_ID=$(microceph.ceph osd pool ls detail | grep "^pool.*'test_pool'" | grep -oP "pool \K\d+")
MAX_OSD_ID=$(microceph.ceph osd ls | sort -n | tail -1)
TOT_PG=$(microceph.ceph osd pool get test_pool pg_num | awk '{print $2}')
info "test_pool id: $TEST_POOL_ID, max OSD id: $MAX_OSD_ID, pg_num: $TOT_PG"

info "=== Step 11: Verify osdtrace output ==="
# 2 MiB random IO / 1 thread / 20 s produces ~100-300 client ops;
# osdtrace fans each write out to subop_w replicas as well, so the
# row total is several hundred.
verify_osdtrace_output "$OSDTRACE_LOG" "$TEST_POOL_ID" "$MAX_OSD_ID" "$TOT_PG" 50

info "=== Step 11b: Verify --id-based osdtrace output ==="
# Anchor the resolver: stdout/stderr of the --id run must report the
# OSD id → PID mapping.  Then run the standard per-row invariant check
# (lower min_rows: a single OSD sees a fraction of the bench traffic,
# but still hundreds of subop_w + op_r rows over 20 s).  Finally pin
# the targets-only invariant: every captured row's osd_id must equal
# $TARGET_OSD_ID, which is the only thing that proves --id attached
# to *that* PID and no others.
if ! grep -q "^--id $TARGET_OSD_ID resolved to PID " "$OSDTRACE_ID_LOG"; then
    err "osdtrace --id $TARGET_OSD_ID log missing 'resolved to PID' line"
    exit 1
fi
verify_osdtrace_output "$OSDTRACE_ID_LOG" "$TEST_POOL_ID" "$MAX_OSD_ID" "$TOT_PG" 10
verify_osdtrace_targets_only "$OSDTRACE_ID_LOG" "$TARGET_OSD_ID"

info "=== Step 12: Verify radostrace output ==="
verify_radostrace_output "$RADOSTRACE_LOG" "$TEST_POOL_ID" "$MAX_OSD_ID" 50

info "=== Step 13: Test hung op detection ==="
HUNG_OP_LOG="/tmp/radostrace_hung.log"

microceph.rados -p test_pool bench 120 write -O 4M --no-cleanup > /dev/null 2>&1 &
BENCH_PID=$!
sleep 1

BENCH_RADOS_PID=""
for i in $(seq 1 30); do
    for pid in $(pgrep -f "rados" 2>/dev/null); do
        if grep -q "librados" /proc/$pid/maps 2>/dev/null; then
            BENCH_RADOS_PID=$pid
            break 2
        fi
    done
    sleep 0.5
done

if [[ -z $BENCH_RADOS_PID ]]; then
    err "Could not find rados bench process with librados for hung op test"
    kill $BENCH_PID 2>/dev/null || true
    exit 1
fi

$PROJECT_ROOT/radostrace -p $BENCH_RADOS_PID -i $RADOS_DWARF --skip-version-check -t 12 \
    >$HUNG_OP_LOG 2>&1 &
RADOSTRACE_HUNG_PID=$!

for i in $(seq 1 30); do
    if grep -q "Started to poll" $HUNG_OP_LOG 2>/dev/null; then
        break
    fi
    sleep 0.5
done

OSD_PIDS=$(pgrep -f "ceph-osd" | tr '\n' ' ')
kill -STOP $OSD_PIDS 2>/dev/null || true
wait $RADOSTRACE_HUNG_PID 2>/dev/null || true
kill -CONT $OSD_PIDS 2>/dev/null || true
kill $BENCH_PID 2>/dev/null || true
wait $BENCH_PID 2>/dev/null || true

if ! awk '$1 ~ /^[0-9]+$/ && NF >= 11 && $10 == "0" { found=1 } END { exit !found }' $HUNG_OP_LOG; then
    err "Expected at least one incomplete op (Complete=0) not found in radostrace output"
    exit 1
fi

rm -f $HUNG_OP_LOG

info "=== Test Summary ==="
info "✓ MicroCeph cluster deployed successfully"
info "✓ osdtrace (-p and --id) and radostrace output validated"
info "✓ All functional tests passed!"

exit 0
