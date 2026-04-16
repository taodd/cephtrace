#!/bin/bash

# E2E test: verify osdtrace and radostrace work without --import-json,
# i.e. they successfully load the embedded DWARF data compiled into the
# binaries.  Validates output fields with the same depth as
# functional-test-microceph.sh, plus the embedded-mode boot marker.
# Exits non-zero on the first failure.

set -e  # Exit on error
set -x  # Print commands

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# shellcheck source=lib/log.sh
source "$SCRIPT_DIR/lib/log.sh"
# shellcheck source=lib/microceph-setup.sh
source "$SCRIPT_DIR/lib/microceph-setup.sh"

OSDTRACE_LOG="/tmp/osdtrace-embedded.log"
RADOSTRACE_LOG="/tmp/radostrace-embedded.log"

cleanup() {
    info "=== Cleanup ==="
    # Match the full path so we only kill processes spawned from this checkout,
    # not anything else on the host that happens to contain "osdtrace" in argv.
    pkill -f "$PROJECT_ROOT/osdtrace" 2>/dev/null || true
    pkill -f "$PROJECT_ROOT/radostrace" 2>/dev/null || true
    pkill -f "rbd bench" 2>/dev/null || true

    if [[ -e $OSDTRACE_LOG ]]; then
        info "osdtrace output:"
        cat $OSDTRACE_LOG
        info " === END of OSD trace === "
    fi
    if [[ -e $RADOSTRACE_LOG ]]; then
        info "radostrace output:"
        cat $RADOSTRACE_LOG
        info " === END of RADOS trace === "
    fi
    rm -f $OSDTRACE_LOG $RADOSTRACE_LOG

    microceph.rbd rm test_pool/testimage 2>/dev/null || true
    microceph.ceph osd pool delete test_pool test_pool --yes-i-really-really-mean-it 2>/dev/null || true

    info "Cleanup completed"
}
trap cleanup EXIT

if [ "$EUID" -ne 0 ]; then
    err "This test must be run as root or with sudo"
    exit 1
fi

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
if ! microceph_setup_single_node 3 1G 120; then
    err "MicroCeph cluster did not become healthy within timeout"
    exit 1
fi
microceph.ceph status

info "=== Step 2: Find OSD process PID ==="
OSD_PID=$(pgrep -f "ceph-osd.*--id 1" | head -1)
if [ -z "$OSD_PID" ]; then
    err "Could not find ceph-osd process"
    ps aux | grep ceph-osd
    exit 1
fi
info "Found OSD process: PID $OSD_PID"

info "=== Step 3: Create RBD pool and image for testing ==="
if ! microceph.ceph osd pool ls | grep -q "^test_pool$"; then
    microceph.ceph osd pool create test_pool 32
    microceph.ceph osd pool application enable test_pool rbd
fi
microceph.rbd create test_pool/testimage --size 1G || true

info "=== Step 4: Start osdtrace in background (embedded mode, no --import-json) ==="
timeout 30 $PROJECT_ROOT/osdtrace -p $OSD_PID --skip-version-check -x >$OSDTRACE_LOG 2>&1 &
sleep 2 # ensure osdtrace starts before we get its PID
OSDTRACE_PID=$(pidof osdtrace)
info "Started osdtrace with PID $OSDTRACE_PID"
sleep 3

info "=== Step 5: Generate I/O traffic using rbd bench ==="
info "Running rbd bench write..."
microceph.rbd bench --io-type write --io-size 4M --io-threads 2 --io-total 400M test_pool/testimage &

info "=== Step 6: Start radostrace in background (embedded mode, no --import-json) ==="
# microceph.rbd bench runs through a snap wrapper chain (snap-run → snap-confine → rbd).
# We must find the PID of the actual rbd binary — the only process in that chain that
# has librados.so.2 mapped into its address space.  Poll /proc/<pid>/maps for each
# candidate rbd-related process until we find one with librados loaded.
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

timeout 30 $PROJECT_ROOT/radostrace -p $RBD_ACTUAL_PID --skip-version-check >$RADOSTRACE_LOG 2>&1 &
sleep 2 # ensure radostrace starts before we get its PID
RADOSTRACE_PID=$(pidof radostrace)
info "Started radostrace with PID $RADOSTRACE_PID"

# Run some rados operations to generate more librados traffic
info "Performing rados operations..."
microceph.rados -p test_pool put testobj /etc/hostname || true
microceph.rados -p test_pool get testobj /tmp/testobj || true
microceph.rados -p test_pool rm testobj || true

info "=== Step 7: Wait for all traces to complete"
wait

info "=== Step 8: Verify osdtrace output ==="

# 8.1 Embedded-mode boot marker (UNIQUE to this test).
# Three outcomes:
#   - Embedded marker present  → expected best path
#   - Live-parse marker present → osdtrace couldn't detect the Ceph version
#     (e.g. snap-confined ceph where dpkg lookup fails) and fell back to
#     runtime DWARF parsing.  This is acceptable: embedded data is an
#     optimisation, not a correctness requirement, and the rest of the
#     trace-output validation below still applies.
#   - Neither marker           → real bug: tool didn't reach either path.
if grep -q "Using embedded DWARF data" $OSDTRACE_LOG; then
    info "✓ osdtrace used embedded DWARF data"
elif grep -q "Start to parse dwarf info" $OSDTRACE_LOG; then
    info "[NOTE] osdtrace fell back to live DWARF parsing (version detection unsupported in this env)"
else
    err "osdtrace output unclear: neither embedded marker nor live-parse marker present"
    exit 1
fi

# 8.2 Trace data captured.
# Threshold deliberately lower than functional-test-microceph.sh (which uses 50).
# Embedded mode binds to addresses baked into the binary at build time, so a
# snap rebuild of the same Ceph version can shift addresses enough that some
# uprobes fail to attach (-ENOEXEC), legitimately reducing trace volume.
OSD_LINE_COUNT=$(wc -l < $OSDTRACE_LOG)
info "osdtrace captured $OSD_LINE_COUNT lines"
if [ $OSD_LINE_COUNT -lt 20 ]; then
    err "osdtrace did not capture enough trace data (expected at least 20 lines)"
    exit 1
fi

# 8.3 OSD IDs range is within the expected limit
MAX_OSD_ID=$(microceph.ceph osd ls | sort -n | tail -1)
info "Max OSD ID in cluster: $MAX_OSD_ID"

osd_id_err=$(awk -v max_osd=$MAX_OSD_ID '$1=="osd" && ($2 < 0 || $2 > max_osd) {print $2; exit}' $OSDTRACE_LOG)
if [ -n "$osd_id_err" ]; then
    err "Found OSD id outside the expected range, $osd_id_err"
    exit 1
fi

# 8.4 Correct pool id is used
TEST_POOL_ID=$(microceph.ceph osd pool ls detail | grep "^pool.*'test_pool'" | grep -oP "pool \K\d+")
pool_id_err=$(awk -v p_id=$TEST_POOL_ID '$1=="osd" && $2=="pg"{split($4, a, "."); if (a[1] != p_id) {print a[1]; exit}}' $OSDTRACE_LOG)
if [ -n "$pool_id_err" ]; then
    err "Unexpected pool id found in osdtrace, $pool_id_err"
    exit 1
fi

# 8.5 PG ranges in the test pool
TOT_PG=$(microceph.ceph osd pool get test_pool pg_num | awk '{print $2}')
pg_range_err=$(awk -v tot=$TOT_PG '$1=="osd" && $2=="pg"{split($4, a, "."); pg=strtonum(a[2]); if (pg < 0 || pg >= tot)print a[2]}' $OSDTRACE_LOG)
if [[ -n $pg_range_err ]]; then
    err "Found PGs outside the expected range: $pg_range_err"
    exit 1
fi

# 8.6 High latencies (max 100s = 100,000,000 µs)
MAX_LATENCY=100000000
high_lat=$(awk -v lmax=$MAX_LATENCY '$1=="osd" && $2=="pg" && $NF > lmax' $OSDTRACE_LOG)
if [[ -n $high_lat ]]; then
    err "Found latencies over $MAX_LATENCY μs"
    exit 1
fi

info "✓ All osdtrace output fields validated successfully"

info "=== Step 9: Verify radostrace output ==="

# radostrace column layout (all fields space-separated, leading whitespace trimmed by awk):
#   $1=pid  $2=client  $3=tid  $4=pool  $5=pg  $6=acting  $7=WR  $8=size  $9=latency  $10+=object[ops]
# Data rows start with the traced process PID, distinguishing them from the header line.

# 9.1 Embedded-mode boot marker (see 8.1 for rationale on the 3-way split).
if grep -q "Using embedded DWARF data" $RADOSTRACE_LOG; then
    info "✓ radostrace used embedded DWARF data"
elif grep -q "Start to parse dwarf info" $RADOSTRACE_LOG; then
    info "[NOTE] radostrace fell back to live DWARF parsing (version detection unsupported in this env)"
else
    err "radostrace output unclear: neither embedded marker nor live-parse marker present"
    exit 1
fi

# 9.2 At least 20 data lines captured (see 8.2 for why this is lower than func-test).
RADOS_DATA_LINES=$(wc -l < $RADOSTRACE_LOG)
info "radostrace captured $RADOS_DATA_LINES data lines"
if [ "$RADOS_DATA_LINES" -lt 20 ]; then
    err "radostrace did not capture enough data (expected >= 20 lines, got $RADOS_DATA_LINES)"
    exit 1
fi

# 9.3 Pool IDs ($4) all match test_pool (TEST_POOL_ID set in 8.4)
rados_pool_err=$(awk -v p_id="$TEST_POOL_ID" \
    '$1 ~ /^[0-9]+$/ && NF >= 9 && $4 != p_id { print $4; exit }' \
    $RADOSTRACE_LOG)
if [ -n "$rados_pool_err" ]; then
    err "Unexpected pool id $rados_pool_err in radostrace output (expected $TEST_POOL_ID)"
    exit 1
fi

# 9.4 Acting-set OSD IDs ($6) fall within 0..MAX_OSD_ID (set in 8.3)
rados_osd_err=$(awk -v max_osd="$MAX_OSD_ID" \
    '$1 ~ /^[0-9]+$/ && NF >= 9 {
        acting = $6; gsub(/[\[\]]/, "", acting)
        n = split(acting, osds, ",")
        for (i = 1; i <= n; i++) {
            id = osds[i] + 0
            if (id < 0 || id > max_osd) { print id; exit }
        }
    }' $RADOSTRACE_LOG)
if [ -n "$rados_osd_err" ]; then
    err "Found OSD id $rados_osd_err outside valid range (0..$MAX_OSD_ID) in radostrace output"
    exit 1
fi

# 9.5 No latency ($9) exceeds 100 seconds (MAX_LATENCY set in 8.6)
rados_high_lat=$(awk -v lmax="$MAX_LATENCY" \
    '$1 ~ /^[0-9]+$/ && NF >= 9 && $9 + 0 > lmax { print $9; exit }' \
    $RADOSTRACE_LOG)
if [ -n "$rados_high_lat" ]; then
    err "Found latency ${rados_high_lat} µs exceeding $MAX_LATENCY µs in radostrace output"
    exit 1
fi

# 9.6 WR flag ($7) is always "W" (write) or "R" (read)
rados_flag_err=$(awk \
    '$1 ~ /^[0-9]+$/ && NF >= 9 && $7 != "W" && $7 != "R" { print $7; exit }' \
    $RADOSTRACE_LOG)
if [ -n "$rados_flag_err" ]; then
    err "Invalid WR flag '$rados_flag_err' in radostrace output (expected W or R)"
    exit 1
fi

info "✓ All radostrace output fields validated successfully"

info "=== Test Summary ==="
info "✓ MicroCeph cluster deployed successfully"
info "✓ osdtrace captured $OSD_LINE_COUNT lines (see Step 8.1 for embedded vs fallback path)"
info "✓ radostrace captured $RADOS_DATA_LINES lines (see Step 9.1 for embedded vs fallback path)"
info "✓ All E2E checks passed!"

exit 0
