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

    if [[ -e $OSDTRACE_LOG ]]; then
        info "OSD trace output:"
        cat $OSDTRACE_LOG
        info " === END of OSD trace === "
    fi

    if [[ -e $RADOSTRACE_LOG ]]; then
        info "RADOS trace output:"
        cat $RADOSTRACE_LOG
        info " === END of RADOS trace === "
    fi

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

info "=== Step 12: Wait for all traces to complete"
wait

info "=== Step 13: Verify osdtrace output ==="

# 13.1 Check trace exists
OSD_LINE_COUNT=$(wc -l < $OSDTRACE_LOG)
info "osdtrace captured $OSD_LINE_COUNT lines"
if [ $OSD_LINE_COUNT -lt 5 ]; then
    err "osdtrace did not capture enough trace data (expected at least 5 lines)"
    exit 1
fi

# 13.2 Check OSD IDs range is within the expected limit
MAX_OSD_ID=$(microceph.ceph osd stat | grep -oP '\d+(?= osds:)' || echo "0")
MAX_OSD_ID=$((MAX_OSD_ID - 1))  # Convert count to max ID (0-indexed)
info "Max OSD ID in cluster: $MAX_OSD_ID"

osd_id_err=$(awk -v max_osd=$MAX_OSD_ID '$1=="osd" && ($2 < 0 || $2 > max_osd) {print $2; exit}' $OSDTRACE_LOG)
if [ -n "$osd_id_err" ]; then
    err "Found OSD id outside the expected range, $osd_id_err"
    exit 1
fi

# 13.3 Check the correct pool id is used
TEST_POOL_ID=$(microceph.ceph osd pool ls detail | grep "^pool.*'test_pool'" | grep -oP "pool \K\d+")
pool_id_err=$(awk -v p_id=$TEST_POOL_ID '$1=="osd" && $2=="pg"{split($4, a, "."); if (a[1] != p_id) {print a[1]; exit}}' $OSDTRACE_LOG)
if [ -n "$pool_id_err" ]; then
    err "Unexpected pool id found in osdtrace, $pool_id_err"
    exit 1
fi

# 13.4 Check PG ranges in the test pool
TOT_PG=$(microceph.ceph osd pool get test_pool pg_num | awk '{print $2}')
pg_range_err=$(awk -v tot=$TOT_PG '$1=="osd" && $2=="pg"{split($4, a, "."); pg=strtonum(a[2]); if (pg < 0 || pg >= tot)print a[2]}' $OSDTRACE_LOG)
if [[ -n $pg_range_err ]]; then
    err "Found PGs outside the expected range: $pg_range_err"
    exit 1
fi

# 13.5 Check for high latencies
# Maximum acceptable latency value (in microseconds) = 100s
MAX_LATENCY=100000000
high_lat=$(awk -v lmax=$MAX_LATENCY '$1=="osd" && $2=="pg" && $NF > lmax' $OSDTRACE_LOG)
if [[ -n $high_lat ]]; then
    err "Found latencies over $MAX_LATENCY μs"
    exit 1
fi

info "✓ All osdtrace output fields validated successfully"

info "===Step 14: Verify radostrace output ==="
RADOS_LINE_COUNT=$(wc -l < $RADOSTRACE_LOG)
info "radostrace captured $RADOS_LINE_COUNT lines"

# 14.1 Check that at least 50 log lines start with 'osd'
RADOS_DATA_LINES=$(awk '$1=="osd"{n++}END{print n}' $RADOSTRACE_LOG)
info "radostrace captured $RADOS_DATA_LINES data lines"

if [ "$RADOS_DATA_LINES" -lt 50 ]; then
    err "radostrace did not capture enough trace data (expected at least 50 lines starting with 'osd')"
    exit 1
fi

# 14.2 Check pool IDs match test_pool
# radostrace output columns: pid client tid pool pg acting WR size latency object[ops]
# Pool ID is field 4 (1-indexed in awk)
if [ -z "$TEST_POOL_ID" ]; then
    TEST_POOL_ID=$(microceph.ceph osd pool ls detail | grep "^pool.*'test_pool'" | grep -oP "pool \K\d+")
fi
rados_pool_err=$(awk -v p_id="$TEST_POOL_ID" \
    '/^[[:space:]]+[0-9]/ && NF >= 9 { if ($4 != p_id) { print $4; exit } }' \
    $RADOSTRACE_LOG)
if [ -n "$rados_pool_err" ]; then
    err "Unexpected pool id $rados_pool_err found in radostrace output (expected pool $TEST_POOL_ID)"
    exit 1
fi

# 14.3 Check OSD IDs in the acting set are within the valid range (0 to MAX_OSD_ID)
# Acting field ($6) has the form [x,y,z]
rados_osd_err=$(awk -v max_osd="$MAX_OSD_ID" \
    '/^[[:space:]]+[0-9]/ && NF >= 9 {
        acting = $6
        gsub(/[\[\]]/, "", acting)
        n = split(acting, osds, ",")
        for (i = 1; i <= n; i++) {
            osd_id = osds[i] + 0
            if (osd_id < 0 || osd_id > max_osd) { print osd_id; exit }
        }
    }' $RADOSTRACE_LOG)
if [ -n "$rados_osd_err" ]; then
    err "Found OSD id $rados_osd_err outside the expected range in radostrace output"
    exit 1
fi

# 14.4 Check for unreasonably high latencies
# Maximum acceptable latency value (in microseconds) = 100s
MAX_LATENCY=100000000
rados_high_lat=$(awk -v lmax="$MAX_LATENCY" \
    '/^[[:space:]]+[0-9]/ && NF >= 9 { if ($9 + 0 > lmax) print $9 }' \
    $RADOSTRACE_LOG)
if [ -n "$rados_high_lat" ]; then
    err "Found latencies over $MAX_LATENCY μs in radostrace output"
    exit 1
fi

# 14.5 Check that the WR flag field contains only valid values (W or R)
rados_flag_err=$(awk \
    '/^[[:space:]]+[0-9]/ && NF >= 9 { if ($7 != "W" && $7 != "R") { print $7; exit } }' \
    $RADOSTRACE_LOG)
if [ -n "$rados_flag_err" ]; then
    err "Found invalid WR flag '$rados_flag_err' in radostrace output (expected W or R)"
    exit 1
fi

info "✓ All radostrace output fields validated successfully"

info "=== Test Summary ==="
info "✓ MicroCeph cluster deployed successfully"
info "✓ osdtrace captured $OSD_LINE_COUNT lines of trace data"
info "✓ radostrace captured $RADOS_LINE_COUNT lines of trace data"
info "✓ All functional tests passed!"

exit 0
