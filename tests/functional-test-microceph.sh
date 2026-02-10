#!/bin/bash

# Functional test for osdtrace and radostrace with MicroCeph
# This test deploys a single-node MicroCeph cluster and verifies that
# osdtrace and radostrace can successfully trace Ceph operations

set -e  # Exit on error
set -x  # Print commands

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== MicroCeph Functional Test for osdtrace and radostrace ==="
echo "Project root: $PROJECT_ROOT"

info() {
    echo "INFO: $@"
}

err() {
    echo "ERROR: $@"
}

OSDTRACE_LOG="/tmp/osdtrace.log"
RADOSTRACE_LOG="/tmp/radostrace.log"

# Cleanup function
cleanup() {
    info "=== Cleanup ==="
    # Kill any running trace processes
    pkill -f osdtrace || true
    pkill -f radostrace || true
    pkill -f "rbd bench" || true

    info "OSD trace output:"
    cat /tmp/osdtrace.log
    info " === END of OSD trace === "
    info "RADOS trace output:"
    cat /tmp/radostrace.log
    info " === END of RADOS trace === "

    # Remove test files
    rm -f $OSDTRACE_LOG $RADOSTRACE_LOG

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

info "=== Step 1: Install MicroCeph ==="
if ! snap list | grep -q microceph; then
    info "Installing MicroCeph snap..."
    snap install microceph
    snap refresh --hold microceph
else
    info "MicroCeph already installed"
fi

info "=== Step 2: Bootstrap MicroCeph cluster ==="
if ! microceph cluster list 2>/dev/null | grep -q "$(hostname)"; then
    info "Bootstrapping MicroCeph cluster..."
    microceph cluster bootstrap
else
    info "MicroCeph cluster already bootstrapped"
fi

info "=== Step 3: Add OSDs ==="
# Check if we already have OSDs
OSD_COUNT=$(microceph.ceph osd stat | grep -oP '\d+(?= osds:)' || echo "0")
if [ "$OSD_COUNT" -lt 3 ]; then
    info "Adding 3 loop-backed OSDs (1GB each)..."
    microceph disk add loop,1G,3
else
    info "Already have $OSD_COUNT OSDs"
fi

info "=== Step 4: Wait for cluster to be healthy ==="
TIMEOUT=120
ELAPSED=0
while [ $ELAPSED -lt $TIMEOUT ]; do
    if microceph.ceph status | grep -q "HEALTH_OK\|HEALTH_WARN"; then
        info "Cluster is ready"
        break
    fi
    info "Waiting for cluster to be ready... ($ELAPSED/$TIMEOUT seconds)"
    sleep 5
    ELAPSED=$((ELAPSED + 5))
done

microceph.ceph status
microceph --version

echo "=== Step 5: Get Ceph version from snap metadata ==="
# Primary: read from snap's metadata.yaml
CEPH_VERSION=$(grep '^ceph-version:' /snap/microceph/current/share/metadata.yaml 2>/dev/null | awk '{print $2}')

# Fallback: parse from snap's manifest.yaml
if [ -z "$CEPH_VERSION" ]; then
    CEPH_VERSION=$(grep 'ceph-osd=' /snap/microceph/current/snap/manifest.yaml | sed 's/.*ceph-osd=//')
fi

info "Ceph version: $CEPH_VERSION"

info "=== Step 6: Locate DWARF JSON files in repository ==="
# Look for matching DWARF files in the repository
OSD_DWARF="$PROJECT_ROOT/files/ubuntu/osdtrace/osd-${CEPH_VERSION}_dwarf.json"
RADOS_DWARF="$PROJECT_ROOT/files/ubuntu/radostrace/${CEPH_VERSION}_dwarf.json"

if [ ! -f "$OSD_DWARF" ]; then
    info "OSD DWARF file not found at $OSD_DWARF"
    info "Looking for any available OSD DWARF files..."
    OSD_DWARF=$(find "$PROJECT_ROOT/files/ubuntu/osdtrace/" -name "*_dwarf.json" | head -1)
    if [ -z "$OSD_DWARF" ]; then
        err "No OSD DWARF files found in repository"
        exit 1
    fi
    info "Using: $OSD_DWARF"
fi

if [ ! -f "$RADOS_DWARF" ]; then
    info "Rados DWARF file not found at $RADOS_DWARF"
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

info "=== Step 7: Find OSD process PID ==="
OSD_PID=$(pgrep -f "ceph-osd.*--id 1" | head -1)
if [ -z "$OSD_PID" ]; then
    err "Could not find ceph-osd process"
    ps aux | grep ceph-osd
    exit 1
fi
info "Found OSD process: PID $OSD_PID"

info "=== Step 8: Create RBD pool and image for testing ==="
# Create RBD pool if it doesn't exist
if ! microceph.ceph osd pool ls | grep -q "^test_pool$"; then
    microceph.ceph osd pool create test_pool 32
    microceph.ceph osd pool application enable test_pool rbd
fi

# Create RBD image
microceph.rbd create test_pool/testimage --size 1G || true

info "=== Step 9: Start osdtrace in background ==="
timeout 30 $PROJECT_ROOT/osdtrace -i $OSD_DWARF -p $OSD_PID --skip-version-check -x >$OSDTRACE_LOG  2>&1 &
sleep 2 # ensure osdtrace starts before we get its PID
OSDTRACE_PID=$(pidof osdtrace)
info "Started osdtrace with PID $OSDTRACE_PID"
sleep 3

info "=== Step 10: Generate I/O traffic using rbd bench ==="
# Run rbd bench for write operations
info "Running rbd bench write..."
microceph.rbd bench --io-type write --io-size 4M --io-threads 4 --io-total 400M test_pool/testimage &
RBD_BENCH_PID=$!

info "=== Step 11: Start radostrace in background ==="
# radostrace will trace all librados clients, including the rbd bench command
timeout 30 $PROJECT_ROOT/radostrace -p $RBD_BENCH_PID -i $RADOS_DWARF --skip-version-check >$RADOSTRACE_LOG 2>&1 &
sleep 2 # ensure radostrace starts before we get its PID
RADOSTRACE_PID=$(pidof radostrace)
info "Started radosdtrace with PID $RADOSTRACE_PID"

# Run some rados operations to generate more librados traffic
info "Performing rados operations..."
microceph.rados -p test_pool put testobj /etc/hostname || true
microceph.rados -p test_pool get testobj /tmp/testobj || true
microceph.rados -p test_pool rm testobj || true

info "=== Step 12: Wait for rbd bench to complete ==="
wait $RBD_BENCH_PID 2>/dev/null || true

info "=== Step 13: Wait for traces to complete ==="
sleep 5

# Kill trace processes gracefully
kill $OSDTRACE_PID 2>/dev/null || true
kill $RADOSTRACE_PID 2>/dev/null || true
wait $OSDTRACE_PID 2>/dev/null || true
wait $RADOSTRACE_PID 2>/dev/null || true

info "=== Step 14: Verify osdtrace output ==="

# 14.1 Check trace exists
OSD_LINE_COUNT=$(wc -l < $OSDTRACE_LOG)
info "osdtrace captured $OSD_LINE_COUNT lines"
if [ $OSD_LINE_COUNT -lt 5 ]; then
    err "osdtrace did not capture enough trace data (expected at least 5 lines)"
    exit 1
fi

# 14.2 Check OSD IDs range is within the expected limit
MAX_OSD_ID=$(microceph.ceph osd stat | grep -oP '\d+(?= osds:)' || echo "0")
MAX_OSD_ID=$((MAX_OSD_ID - 1))  # Convert count to max ID (0-indexed)
info "Max OSD ID in cluster: $MAX_OSD_ID"

osd_id_err=$(awk -v max_osd=$MAX_OSD_ID '$1=="osd" && ($2 < 0 || $2 > max_osd) {print $2; exit}' $OSDTRACE_LOG)
if [ -n "$osd_id_err" ]; then
    err "Found OSD id outside the expected range, $osd_id_err"
    exit 1
fi

# 14.3 Check the correct pool id is used
TEST_POOL_ID=$(microceph.ceph osd pool ls detail | grep "^pool.*'test_pool'" | grep -oP "pool \K\d+")
pool_id_err=$(awk -v p_id=$TEST_POOL_ID '$1=="osd" && $2=="pg"{split($4, a, "."); if (a[1] != p_id) {print a[1]; exit}}' $OSDTRACE_LOG)
if [ -n "$pool_id_err" ]; then
    err "Unexpected pool id found in osdtrace, $pool_id_err"
    exit 1
fi

# 14.4 Check PG ranges in the test pool
TOT_PG=$(microceph.ceph osd pool get test_pool pg_num | awk '{print $2}')
pg_range_err=$(awk -v tot=$TOT_PG '$1=="osd" && $2=="pg"{split($4, a, "."); pg=strtonum(a[2]); if (pg < 0 || pg >= tot)print a[2]}' $OSDTRACE_LOG)
if [[ -n $pg_range_err ]]; then
    err "Found PGs outside the expected range: $pg_range_err"
    exit 1
fi

# 14.5 Check for high latencies
# Maximum acceptable latency value (in microseconds) = 100s
MAX_LATENCY=100000000
high_lat=$(awk -v lmax=$MAX_LATENCY '$1=="osd" && $2=="pg" && $NF > lmax' $OSDTRACE_LOG)
if [[ -n $high_lat ]]; then
    err "Found latencies over $MAX_LATENCY μs"
    exit 1
fi

info "✓ All osdtrace output fields validated successfully"

info "===Step 15: Verify radostrace output ==="
RADOS_LINE_COUNT=$(wc -l < $RADOSTRACE_LOG)
info "radostrace captured $RADOS_LINE_COUNT lines"

if [ $RADOS_LINE_COUNT -lt 3 ]; then
    err "radostrace did not capture enough trace data (expected at least 3 lines)"
    exit 1
fi

info "✓ radostrace successfully captured trace data"

info "=== Test Summary ==="
info "✓ MicroCeph cluster deployed successfully"
info "✓ osdtrace captured $OSD_LINE_COUNT lines of trace data"
info "✓ radostrace captured $RADOS_LINE_COUNT lines of trace data"
info "✓ All functional tests passed!"

exit 0
