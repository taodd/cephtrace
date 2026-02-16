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

# Cleanup function
cleanup() {
    echo "=== Cleanup ==="
    # Kill any running trace processes
    pkill -f osdtrace || true
    pkill -f radostrace || true
    pkill -f "rbd bench" || true

    # Remove test files
    rm -f /tmp/osdtrace.log /tmp/radostrace.log

    # Remove test RBD resources
    microceph.rbd rm test_pool/testimage 2>/dev/null || true
    microceph.ceph osd pool delete test_pool test_pool --yes-i-really-really-mean-it 2>/dev/null || true

    echo "Cleanup completed"
}

trap cleanup EXIT

# Check if running as root or with sudo
if [ "$EUID" -ne 0 ]; then
    echo "Error: This test must be run as root or with sudo"
    exit 1
fi

# Check if osdtrace and radostrace binaries exist
if [ ! -f "$PROJECT_ROOT/osdtrace" ]; then
    echo "Error: osdtrace binary not found at $PROJECT_ROOT/osdtrace"
    echo "Please build the project first with 'make osdtrace'"
    exit 1
fi

if [ ! -f "$PROJECT_ROOT/radostrace" ]; then
    echo "Error: radostrace binary not found at $PROJECT_ROOT/radostrace"
    echo "Please build the project first with 'make radostrace'"
    exit 1
fi

echo "=== Step 1: Install MicroCeph ==="
if ! snap list | grep -q microceph; then
    echo "Installing MicroCeph snap..."
    snap install microceph
    snap refresh --hold microceph
else
    echo "MicroCeph already installed"
fi

echo "=== Step 2: Bootstrap MicroCeph cluster ==="
if ! microceph cluster list 2>/dev/null | grep -q "$(hostname)"; then
    echo "Bootstrapping MicroCeph cluster..."
    microceph cluster bootstrap
else
    echo "MicroCeph cluster already bootstrapped"
fi

echo "=== Step 3: Add OSDs ==="
# Check if we already have OSDs
OSD_COUNT=$(microceph.ceph osd stat | grep -oP '\d+(?= osds:)' || echo "0")
if [ "$OSD_COUNT" -lt 3 ]; then
    echo "Adding 3 loop-backed OSDs (1GB each)..."
    microceph disk add loop,1G,3
else
    echo "Already have $OSD_COUNT OSDs"
fi

echo "=== Step 4: Wait for cluster to be healthy ==="
TIMEOUT=120
ELAPSED=0
while [ $ELAPSED -lt $TIMEOUT ]; do
    if microceph.ceph status | grep -q "HEALTH_OK\|HEALTH_WARN"; then
        echo "Cluster is ready"
        break
    fi
    echo "Waiting for cluster to be ready... ($ELAPSED/$TIMEOUT seconds)"
    sleep 5
    ELAPSED=$((ELAPSED + 5))
done

microceph.ceph status

echo "=== Step 5: Get Ceph version from snap manifest ==="
CEPH_VERSION=$(cat /snap/microceph/current/snap/manifest.yaml | grep "^ceph-osd:" | awk '{print $2}')
LIBRADOS_VERSION=$(cat /snap/microceph/current/snap/manifest.yaml | grep "^librados2:" | awk '{print $2}')

echo "Ceph OSD version: $CEPH_VERSION"
echo "Librados version: $LIBRADOS_VERSION"

echo "=== Step 6: Locate DWARF JSON files in repository ==="
# Look for matching DWARF files in the repository
OSD_DWARF="$PROJECT_ROOT/files/ubuntu/osdtrace/osd-${CEPH_VERSION}_dwarf.json"
RADOS_DWARF="$PROJECT_ROOT/files/ubuntu/radostrace/${LIBRADOS_VERSION}_dwarf.json"

if [ ! -f "$OSD_DWARF" ]; then
    echo "Warning: OSD DWARF file not found at $OSD_DWARF"
    echo "Looking for any available OSD DWARF files..."
    OSD_DWARF=$(find "$PROJECT_ROOT/files/ubuntu/osdtrace/" -name "*_dwarf.json" | head -1)
    if [ -z "$OSD_DWARF" ]; then
        echo "Error: No OSD DWARF files found in repository"
        exit 1
    fi
    echo "Using: $OSD_DWARF"
fi

if [ ! -f "$RADOS_DWARF" ]; then
    echo "Warning: Rados DWARF file not found at $RADOS_DWARF"
    echo "Looking for any available radostrace DWARF files..."
    RADOS_DWARF=$(find "$PROJECT_ROOT/files/ubuntu/radostrace/" -name "*_dwarf.json" | head -1)
    if [ -z "$RADOS_DWARF" ]; then
        echo "Error: No radostrace DWARF files found in repository"
        exit 1
    fi
    echo "Using: $RADOS_DWARF"
fi

echo "Using OSD DWARF file: $OSD_DWARF"
echo "Using Rados DWARF file: $RADOS_DWARF"

echo "=== Step 7: Find OSD process PID ==="
OSD_PID=$(pgrep -f "ceph-osd.*--id 1" | head -1)
if [ -z "$OSD_PID" ]; then
    echo "Error: Could not find ceph-osd process"
    ps aux | grep ceph-osd
    exit 1
fi
echo "Found OSD process: PID $OSD_PID"

echo "=== Step 8: Create RBD pool and image for testing ==="
# Create RBD pool if it doesn't exist
if ! microceph.ceph osd pool ls | grep -q "^test_pool$"; then
    microceph.ceph osd pool create test_pool 32
    microceph.ceph osd pool application enable test_pool rbd
fi

# Create RBD image
microceph.rbd create test_pool/testimage --size 1G || true

echo "=== Step 9: Start osdtrace in background ==="
timeout 30 $PROJECT_ROOT/osdtrace -i $OSD_DWARF -p $OSD_PID --skip-version-check -x > /tmp/osdtrace.log 2>&1 &
OSDTRACE_PID=$!
echo "Started osdtrace with PID $OSDTRACE_PID"
sleep 3

echo "=== Step 10: Start radostrace in background ==="
# radostrace will trace all librados clients, including the rbd bench command
timeout 30 $PROJECT_ROOT/radostrace -i $RADOS_DWARF --skip-version-check > /tmp/radostrace.log 2>&1 &
RADOSTRACE_PID=$!
echo "Started radostrace with PID $RADOSTRACE_PID"
sleep 3

echo "=== Step 11: Generate I/O traffic using rbd bench ==="
# Run rbd bench for write operations
echo "Running rbd bench write..."
microceph.rbd bench --io-type write --io-size 4M --io-threads 4 --io-total 100M test_pool/testimage &
RBD_BENCH_PID=$!

# Wait a bit for some I/O to occur
sleep 10

# Run some rados operations to generate more librados traffic
echo "Performing rados operations..."
microceph.rados -p test_pool put testobj /etc/hostname || true
microceph.rados -p test_pool get testobj /tmp/testobj || true
microceph.rados -p test_pool rm testobj || true

echo "=== Step 12: Wait for rbd bench to complete ==="
wait $RBD_BENCH_PID 2>/dev/null || true

echo "=== Step 13: Wait for traces to complete ==="
sleep 5

# Kill trace processes gracefully
kill $OSDTRACE_PID 2>/dev/null || true
kill $RADOSTRACE_PID 2>/dev/null || true
wait $OSDTRACE_PID 2>/dev/null || true
wait $RADOSTRACE_PID 2>/dev/null || true

echo "=== Step 14: Verify osdtrace output ==="
if [ ! -f /tmp/osdtrace.log ]; then
    echo "Error: osdtrace log file not found"
    exit 1
fi

OSD_LINE_COUNT=$(wc -l < /tmp/osdtrace.log)
echo "osdtrace captured $OSD_LINE_COUNT lines"

if [ $OSD_LINE_COUNT -lt 5 ]; then
    echo "Error: osdtrace did not capture enough trace data (expected at least 5 lines)"
    echo "osdtrace output:"
    cat /tmp/osdtrace.log
    exit 1
fi

echo "✓ osdtrace successfully captured trace data"

echo "=== Step 15: Verify radostrace output ==="
if [ ! -f /tmp/radostrace.log ]; then
    echo "Error: radostrace log file not found"
    exit 1
fi

RADOS_LINE_COUNT=$(wc -l < /tmp/radostrace.log)
echo "radostrace captured $RADOS_LINE_COUNT lines"

if [ $RADOS_LINE_COUNT -lt 3 ]; then
    echo "Error: radostrace did not capture enough trace data (expected at least 3 lines)"
    echo "radostrace output:"
    cat /tmp/radostrace.log
    exit 1
fi

echo "✓ radostrace successfully captured trace data"

echo ""
echo "=== Test Summary ==="
echo "✓ MicroCeph cluster deployed successfully"
echo "✓ osdtrace captured $OSD_LINE_COUNT lines of trace data"
echo "✓ radostrace captured $RADOS_LINE_COUNT lines of trace data"
echo "✓ All functional tests passed!"
echo ""
echo "Sample osdtrace output (first 10 lines):"
cat /tmp/osdtrace.log
echo ""
echo "Sample radostrace output (first 10 lines):"
cat /tmp/radostrace.log

exit 0
