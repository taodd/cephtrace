#!/bin/bash
#
# End-to-end test: deploy a single-host cephadm cluster (1 MON+MGR, 3 OSDs,
# 1 radosgw) for a target Ceph major release, drive S3 traffic through the
# RGW, and trace BOTH:
#   - the radosgw daemon with radostrace      (librados client path)
#   - one ceph-osd daemon with osdtrace       (server-side OSD path)
# simultaneously, then validate that both produce expected trace output.
#
# Usage:
#   sudo ./tests/functional-test-cephadm-rgw.sh <release>
#       release ∈ { quincy | reef | squid | tentacle }
#
# Expects $PROJECT_ROOT/osdtrace and $PROJECT_ROOT/radostrace to be built.

set -e
set -x

CEPH_RELEASE="${1:?usage: $0 <quincy|reef|squid|tentacle>}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# shellcheck source=lib/log.sh
source "$SCRIPT_DIR/lib/log.sh"
# shellcheck source=lib/cephadm-setup.sh
source "$SCRIPT_DIR/lib/cephadm-setup.sh"
# shellcheck source=lib/verify-trace-output.sh
source "$SCRIPT_DIR/lib/verify-trace-output.sh"
# shellcheck source=lib/verify-list-output.sh
source "$SCRIPT_DIR/lib/verify-list-output.sh"

OSDTRACE_LOG="/tmp/osdtrace-cephadm-${CEPH_RELEASE}.log"
RADOSTRACE_LOG="/tmp/radostrace-cephadm-${CEPH_RELEASE}.log"
WORKLOAD_LOG="/tmp/s3-workload-${CEPH_RELEASE}.log"
S3CFG="/root/.s3cfg-cephadm-test"

# Trace sustained read+write window.  Long enough to overlap radostrace's
# uprobe attach + the workload's steady-state phase.
TRACE_SECONDS=45
# osdtrace counts only rows targeting the chosen RGW data pool; that pool
# carries the S3 object payloads, so it dominates traffic but is a strict
# subset of the total trace volume.
MIN_OSD_ROWS=20
MIN_RGW_ROWS=50

FSID=""

cleanup() {
    local rc=$?
    info "=== Cleanup ==="
    pkill -f "$PROJECT_ROOT/osdtrace" 2>/dev/null || true
    pkill -f "$PROJECT_ROOT/radostrace" 2>/dev/null || true
    pkill -f "s3cmd" 2>/dev/null || true
    pkill -f "rados bench" 2>/dev/null || true
    if [[ -e "$OSDTRACE_LOG" ]]; then
        info "--- osdtrace tail (last 50 lines) ---"
        tail -50 "$OSDTRACE_LOG" || true
    fi
    if [[ -e "$RADOSTRACE_LOG" ]]; then
        info "--- radostrace tail (last 50 lines) ---"
        tail -50 "$RADOSTRACE_LOG" || true
    fi
    if [[ -n "$FSID" ]]; then
        info "--- final ceph -s ---"
        cephadm shell --fsid "$FSID" -- ceph -s 2>/dev/null || true
        if [[ "${KEEP_CLUSTER:-0}" -eq 1 ]]; then
            info "KEEP_CLUSTER=1 — leaving cluster $FSID intact for inspection"
        else
            cleanup_cephadm_cluster "$FSID" || true
        fi
    fi
    # Preserve trace logs on failure (rc != 0) so the GHA artifact-upload
    # step in .github/workflows/pr-build.yaml has the full file to attach;
    # cleanup_cephadm_cluster already wiped the runtime state, so the only
    # remaining cost is a few MB of log on the runner's tmpfs.  Also keep
    # them when KEEP_CLUSTER=1 (developer is iterating locally).
    if [[ $rc -eq 0 && "${KEEP_CLUSTER:-0}" -ne 1 ]]; then
        rm -f "$S3CFG" "$OSDTRACE_LOG" "$RADOSTRACE_LOG" "$WORKLOAD_LOG" 2>/dev/null || true
    else
        info "Preserving trace logs at $OSDTRACE_LOG / $RADOSTRACE_LOG (exit=$rc)"
    fi
    info "cleanup done"
}
trap cleanup EXIT

[ "$EUID" -eq 0 ] || { err "must run as root"; exit 1; }
[ -x "$PROJECT_ROOT/osdtrace" ]   || { err "osdtrace not built (run 'make all' first)"; exit 1; }
[ -x "$PROJECT_ROOT/radostrace" ] || { err "radostrace not built (run 'make all' first)"; exit 1; }


############################################################################
info "=== Step 1: install host deps (podman, s3cmd, lvm2) ==="
export DEBIAN_FRONTEND=noninteractive
apt-get update -q

# GitHub's ubuntu-22.04/24.04 runner images (>= 20260810, runner-images
# #14412) untar the mgoltzsche/podman-static 5.8.4 bundle into /usr/local
# (podman, crun, runc, conmon, netavark, aardvark-dns, pasta,
# fuse-overlayfs, systemd units) and drop its config into /etc/containers
# (containers.conf, storage.conf, seccomp.json, plus containers.conf.d
# drop-ins pinning crun to /usr/local/bin/crun).  Ubuntu 26.04 gets podman
# from apt and is unaffected.
#
# That bundle breaks this test two ways.  With /usr/local/bin/podman
# first on PATH, cephadm resolves the engine to the 5.8.4 static binary
# and the mon container fails to start during bootstrap.  Even with the
# distro podman installed below and first on PATH, podman's built-in
# conmon search order prefers /usr/local/lib/podman/conmon -- built
# without journald -- so every `podman run` dies with exit 126
# "[conmon:e]: Include journald in compilation path to log to systemd
# journal", and the drop-ins still route it to the bundle's crun.
#
# Strip the bundle, its config and any container-storage state its podman
# initialised (the image build ran `podman network reload` as root, which
# creates a 5.x sqlite libpod DB under /var/lib/containers) so the host
# looks like a stock Ubuntu box, then install the distro podman this test
# has always run against.  Keyed on the bundle's own layout
# (/usr/local/lib/podman/conmon) rather than just /usr/local/bin/podman so
# a hand-installed podman on a developer machine is left alone.
if [ -x /usr/local/bin/podman ] && [ -x /usr/local/lib/podman/conmon ]; then
    info "removing runner-image static podman bundle ($(/usr/local/bin/podman --version 2>/dev/null | head -1))"
    systemctl disable --now podman.socket podman.service podman-restart.service 2>/dev/null || true
    rm -f /usr/local/bin/podman /usr/local/bin/crun /usr/local/bin/runc \
          /usr/local/bin/pasta /usr/local/bin/pasta.avx2 \
          /usr/local/bin/fuse-overlayfs /usr/local/bin/fusermount3
    rm -rf /usr/local/lib/podman /usr/local/libexec/podman
    rm -f /usr/local/lib/systemd/system/podman.socket \
          /usr/local/lib/systemd/system/podman.service \
          /usr/local/lib/systemd/system/podman-restart.service \
          /usr/local/lib/systemd/user/podman.socket \
          /usr/local/lib/systemd/user/podman.service \
          /usr/local/lib/systemd/user/podman-restart.service \
          /usr/local/lib/systemd/system-generators/podman-system-generator \
          /usr/local/lib/systemd/user-generators/podman-user-generator
    rm -f /etc/containers/containers.conf /etc/containers/storage.conf \
          /etc/containers/seccomp.json \
          /etc/containers/containers.conf.d/00-fix-runtime.conf \
          /etc/containers/containers.conf.d/99-fix-firewall.conf
    rm -rf /var/lib/containers/storage /var/lib/containers/cache \
           /run/containers/storage /run/libpod
    systemctl daemon-reload 2>/dev/null || true
    hash -r 2>/dev/null || true
fi

apt-get install -y -q podman s3cmd python3 curl lvm2 gdisk parted

# Quincy's bundled cephadm (v17.2.x) has a buggy `_fetch_apparmor` that
# splits each /sys/kernel/security/apparmor/profiles line by a single
# space (`item, mode = line.split(' ')`).  Ubuntu 24.04 ships an apparmor
# profile declared as `profile "MongoDB Compass" ...` -- the profile
# *name* contains a literal space, so the kernel exposes it in
# /sys/kernel/security/apparmor/profiles as `MongoDB Compass (unconfined)`
# (3 space-separated tokens), which triggers
# ValueError("too many values to unpack") inside the mgr's orchestrator
# and silently fails the OSD apply.
#
# None of the apparmor profiles in /etc/apparmor.d/ are relevant to this
# headless test VM (they cover desktop apps like 1password, Discord, the
# offending MongoDB Compass, etc).  Unload all of them so the
# /sys/kernel/security/apparmor/profiles file the quincy cephadm parser
# reads no longer contains any space-named profile.  No-op for the
# already-loaded profiles cephadm/podman uses (containers-default-* and
# docker-default); those have no spaces in their names and we leave them
# alone implicitly because we only target /etc/apparmor.d/* files.
if command -v apparmor_parser >/dev/null; then
    while IFS= read -r profile_file; do
        apparmor_parser -R "$profile_file" 2>/dev/null || true
    done < <(find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null)
fi


############################################################################
info "=== Step 2: install cephadm + resolve image for $CEPH_RELEASE ==="
# CEPH_IMAGE lets a caller pin an exact point-release image
# (e.g. quay.io/ceph/ceph:v19.2.2) instead of the per-major "latest"
# default.  The embedded-DWARF refresh bot uses this to run the verification
# against the precise version it just generated a JSON for, so the build_id
# matches and the embedded path actually engages.
if [ -n "${CEPH_IMAGE:-}" ]; then
    CEPH_IMG="$CEPH_IMAGE"
else
    CEPH_IMG=$(cephadm_image_for_release "$CEPH_RELEASE")
fi
info "image: $CEPH_IMG"
install_cephadm "$CEPH_RELEASE" /tmp/cephadm "$CEPH_IMG"


############################################################################
info "=== Step 3: provision 3 loopback OSD devices (3 GiB each) ==="
mapfile -t OSD_DEVS < <(provision_loopback_osds 3 3)
losetup -l
info "OSD devices: ${OSD_DEVS[*]}"


############################################################################
info "=== Step 4: bootstrap single-host cephadm cluster ==="
MON_IP=$(hostname -I | awk '{print $1}')
info "MON_IP=$MON_IP"
FSID=$(cephadm_bootstrap_single_host "$CEPH_IMG" "$MON_IP" /tmp/cephadm) || true
[ -n "$FSID" ] || { err "bootstrap failed to produce FSID"; exit 1; }
info "FSID=$FSID"


############################################################################
info "=== Step 5: apply OSD spec with explicit device paths ==="
# Why not `ceph orch apply osd --all-available-devices`?
#   - `ceph orch device ls` only enumerates devices that ceph-volume's
#     inventory considers candidates, and inventory filters out
#     /dev/loopX entirely (loops aren't rotational disks); even after
#     wrapping each loop in LVM the LV nodes (/dev/mapper/*) are not
#     bind-mounted into the cephadm shell container, so inventory still
#     can't see them and returns empty.
#
# Why a single `orch apply osd <spec>` and not three `daemon add osd` calls?
#   - daemon-add is async-queued by the orchestrator.  Firing three calls
#     in rapid succession races the orchestrator's state machine: the
#     second/third often return "Created no osd(s); already created?" and
#     only 1-2 OSDs actually come up.  A single apply with all paths is
#     processed atomically by the orchestrator's OSD planner.
HOSTNAME_SHORT=$(hostname -s)
OSD_SPEC=/tmp/osd-spec.yaml
{
    echo "service_type: osd"
    echo "service_id: test-osds"
    echo "placement:"
    echo "  hosts: ['${HOSTNAME_SHORT}']"
    echo "data_devices:"
    echo "  paths:"
    for dev in "${OSD_DEVS[@]}"; do
        echo "  - ${dev}"
    done
} > "$OSD_SPEC"
cat "$OSD_SPEC"
# `cephadm shell` mounts /root from the host, so we can reference the
# spec file from inside the container via its /root path.
cephadm shell --fsid "$FSID" --mount "$OSD_SPEC:/tmp/osd-spec.yaml" -- \
    ceph orch apply -i /tmp/osd-spec.yaml

info "=== Step 6: wait for cluster healthy (1 MON + 1 MGR + 3 OSDs up) ==="
if ! wait_cephadm_healthy "$FSID" 3 900; then
    err "cluster did not become ready"
    exit 1
fi


############################################################################
info "=== Step 7: deploy RGW (1 instance, port 8080) ==="
if ! apply_rgw_service "$FSID" test 8080; then
    err "RGW deployment failed"
    exit 1
fi


############################################################################
info "=== Step 8: create RGW user + write S3 config ==="
ACCESS_KEY="rgwtestaccesskey"
SECRET_KEY="rgwtestsecretkeyrgwtestsecretkey"
create_rgw_user "$FSID" testuser "$ACCESS_KEY" "$SECRET_KEY"
cat > "$S3CFG" <<EOF
[default]
access_key = $ACCESS_KEY
secret_key = $SECRET_KEY
host_base  = ${MON_IP}:8080
host_bucket = ${MON_IP}:8080/%(bucket)
use_https = False
signature_v2 = False
check_ssl_certificate = False
EOF
S3="s3cmd --config=$S3CFG"


############################################################################
info "=== Step 9: create bucket + warm-up so RGW pools auto-create ==="
$S3 mb s3://testbucket >>"$WORKLOAD_LOG" 2>&1
for i in 1 2 3 4 5; do
    echo "warmup-$i" | $S3 put - "s3://testbucket/warmup-$i" >>"$WORKLOAD_LOG" 2>&1 || true
done
sleep 3   # let any default.rgw.* pools settle


############################################################################
info "=== Step 10: identify PIDs to trace ==="
# `radosgw -n client.rgw.test.<host>.<random>` runs on this host as a podman
# container's main process; pgrep finds the HOST-side PID (via shared PID
# namespace), which is what uprobe needs.  cephadm uses `-n <name>`, NOT
# `--id <name>`.
#
# Anchoring with `^[^ ]*<binary>` is critical: cephadm starts each daemon
# under `/run/podman-init -- /usr/bin/<binary> -n ...`.  Without the anchor,
# pgrep returns the podman-init PID (whose cmdline contains "ceph-osd" as
# a later argv), and osdtrace/radostrace then fail with "Process is
# running: /run/podman-init".
RGW_PID=$(pgrep -f "^[^ ]*radosgw .*-n[[:space:]]+client\.rgw\.test\." | head -1)
[ -n "$RGW_PID" ] || { err "could not find radosgw PID"; pgrep -af radosgw; exit 1; }

# Trace osd.1 specifically — picking a non-zero id makes the test resilient
# to the orchestrator renumbering OSDs across re-runs.  cephadm runs OSDs
# as `ceph-osd -n osd.<id>` (not `--id <id>`).
OSD_PID=$(pgrep -f "^[^ ]*ceph-osd .*-n[[:space:]]+osd\.1\b" | head -1)
[ -n "$OSD_PID" ] || OSD_PID=$(pgrep -f "^[^ ]*ceph-osd .*-n[[:space:]]+osd\.[0-9]" | head -1)
[ -n "$OSD_PID" ] || { err "could not find ceph-osd PID"; pgrep -af ceph-osd; exit 1; }

info "RGW PID=$RGW_PID, OSD PID=$OSD_PID"


############################################################################
info "=== Step 10b: verify --list output over a multi-client host ==="
# At this point the host runs a containerized MON, MGR, 3 OSDs, and the
# radosgw.  Add one *native* (non-container) librados client - a host-side
# rados bench - so --list must classify a mixed population: containerized
# daemons (Container=yes, version = the container image's Ceph) alongside
# a native client (Container=no, version = the host package).
apt-get install -y -q ceph-common

# The argument is a release name from PR CI (quincy/reef/squid/tentacle) but a
# bare version number from the embedded-DWARF refresh bot (e.g. "20.2.2", with
# CEPH_IMAGE pinned).  Map either form to the expected Ceph major - the
# containerized rows must all report a version of this major.
case "$CEPH_RELEASE" in
    quincy)   EXPECTED_MAJOR=17 ;;
    reef)     EXPECTED_MAJOR=18 ;;
    squid)    EXPECTED_MAJOR=19 ;;
    tentacle) EXPECTED_MAJOR=20 ;;
    [0-9]*)   EXPECTED_MAJOR=$(_version_major "$CEPH_RELEASE") ;;  # 20.2.2 -> 20
    *) err "unknown release '$CEPH_RELEASE'"; exit 1 ;;
esac

cephadm shell --fsid "$FSID" -- ceph osd pool create list-test 8 >>"$WORKLOAD_LOG" 2>&1
cephadm shell --fsid "$FSID" -- ceph osd pool application enable list-test rados >>"$WORKLOAD_LOG" 2>&1

# Long-running native client; killed + cleaned up right after the checks.
# The host rados CLI may be a different (newer/older) major than the
# cluster - fine for bench I/O, and exactly the mixed-version situation
# --list's per-process version resolution must get right.
rados bench -p list-test 120 write -b 4096 --no-cleanup >>"$WORKLOAD_LOG" 2>&1 &
BENCH_PID=$!
sleep 3   # let it connect so libceph-common is mapped
kill -0 "$BENCH_PID" 2>/dev/null || { err "native rados bench died at startup"; tail -5 "$WORKLOAD_LOG"; exit 1; }

HOST_LIBRADOS_VER=$(dpkg-query -W -f='${Version}' librados2)
info "native client: rados bench pid=$BENCH_PID, host librados2=$HOST_LIBRADOS_VER"

verify_radostrace_list_multiclient "$PROJECT_ROOT/radostrace" \
    "$EXPECTED_MAJOR" "$BENCH_PID" "$HOST_LIBRADOS_VER"
verify_osdtrace_list_multiosd "$PROJECT_ROOT/osdtrace" "$EXPECTED_MAJOR" 3

kill "$BENCH_PID" 2>/dev/null || true
wait "$BENCH_PID" 2>/dev/null || true
# No benchmark objects left behind; drop the throwaway pool entirely.
rados -p list-test cleanup >>"$WORKLOAD_LOG" 2>&1 || true
cephadm shell --fsid "$FSID" -- ceph config set mon mon_allow_pool_delete true >>"$WORKLOAD_LOG" 2>&1 || true
cephadm shell --fsid "$FSID" -- ceph osd pool rm list-test list-test \
    --yes-i-really-really-mean-it >>"$WORKLOAD_LOG" 2>&1 || true


############################################################################
info "=== Step 11: start traces (osdtrace + radostrace in parallel) ==="
# osdtrace prints full per-event row format by default.
timeout "$TRACE_SECONDS" "$PROJECT_ROOT/osdtrace"   -p "$OSD_PID" >"$OSDTRACE_LOG"   2>&1 &
timeout "$TRACE_SECONDS" "$PROJECT_ROOT/radostrace" -p "$RGW_PID"    >"$RADOSTRACE_LOG" 2>&1 &

# Give each tool a few seconds to parse DWARF and attach uprobes before
# we start hammering the cluster — otherwise the first ~3 s of workload
# fire before the probes are live and we under-count.
sleep 6


############################################################################
info "=== Step 12: drive S3 workload (mixed PUT + GET) ==="
# Two parallel loops keep the OSD and the RGW busy through the entire
# trace window.  Object size varies between 8 KB and 256 KB so we get a
# meaningful spread of librados ops (data write + index update + log).
(
    set +e
    for i in $(seq 1 800); do
        # mix object sizes for op-pattern diversity
        head -c $((RANDOM % 262144 + 8192)) /dev/urandom \
          | $S3 put - "s3://testbucket/obj-$i" >>"$WORKLOAD_LOG" 2>&1
    done
) &
WL_PUT=$!

(
    set +e
    sleep 3
    for i in $(seq 1 800); do
        $S3 get "s3://testbucket/obj-$i" "/tmp/get-$i" >>"$WORKLOAD_LOG" 2>&1
        rm -f "/tmp/get-$i"
    done
) &
WL_GET=$!


############################################################################
info "=== Step 13: wait for traces to finish (TRACE_SECONDS=${TRACE_SECONDS}) ==="
wait

# Kill any still-running workload loops (they will have produced their
# share by now, but a slow s3cmd on a constrained runner can outlast the
# trace window).
kill "$WL_PUT" "$WL_GET" 2>/dev/null || true
sleep 2


############################################################################
info "=== Step 13b: check embedded-DWARF boot marker ==="
# When REQUIRE_EMBEDDED=1 (the refresh bot's per-version verification), the
# whole point is to prove the *embedded* JSON works: a fallback to live DWARF
# parsing means the embedded data was never exercised, so treat it as a hard
# failure.  Without the flag (the normal PR matrix) the marker is advisory --
# the major-release "latest" image may legitimately predate or postdate the
# embedded data, and live-parse fallback is an acceptable optimisation miss.
check_embedded_marker() {
    local tool="$1" log="$2"
    if grep -q "Using embedded DWARF data" "$log"; then
        info "✓ $tool used embedded DWARF data"
        return 0
    fi
    if [ "${REQUIRE_EMBEDDED:-0}" = "1" ]; then
        err "$tool did NOT use embedded DWARF data (REQUIRE_EMBEDDED=1)"
        if grep -q "Start to parse dwarf info" "$log"; then
            err "  -> it fell back to live DWARF parsing; the embedded JSON for this version was not matched (build_id mismatch?)"
        else
            err "  -> neither embedded nor live-parse marker present; tool may have failed to start"
        fi
        return 1
    fi
    if grep -q "Start to parse dwarf info" "$log"; then
        info "[NOTE] $tool fell back to live DWARF parsing (embedded data not matched in this env)"
    else
        info "[NOTE] $tool: no embedded/live-parse marker found"
    fi
    return 0
}
check_embedded_marker osdtrace   "$OSDTRACE_LOG"
check_embedded_marker radostrace "$RADOSTRACE_LOG"


############################################################################
info "=== Step 14: gather cluster facts for verifiers ==="
# osdtrace counts data rows targeting a single pool; pick the RGW data
# pool (.rgw.buckets.data) because it carries the S3 object payloads
# and therefore dominates osd traffic during the workload.  The other
# RGW pools (.rgw.meta, .rgw.buckets.index, .rgw.log, ...) are still
# checked by the per-row OSD-id/latency invariants, just not by the
# per-pool PG / row-count thresholds.
MAX_OSD_ID=$(cephadm shell --fsid "$FSID" -- ceph osd ls 2>/dev/null | sort -n | tail -1)
DATA_POOL_NAME=$(cephadm shell --fsid "$FSID" -- ceph osd pool ls 2>/dev/null \
    | grep -E '\.rgw\.buckets\.data$' | head -1)
DATA_POOL_ID=$(cephadm shell --fsid "$FSID" -- ceph osd pool ls detail 2>/dev/null \
    | grep "^pool.*'${DATA_POOL_NAME}'" | grep -oP "pool \K\d+")
DATA_POOL_PG_NUM=$(cephadm shell --fsid "$FSID" -- \
    ceph osd pool get "$DATA_POOL_NAME" pg_num 2>/dev/null | awk '{print $2}')
info "max OSD id: $MAX_OSD_ID, RGW data pool: $DATA_POOL_NAME (id=$DATA_POOL_ID, pg_num=$DATA_POOL_PG_NUM)"
[ -n "$DATA_POOL_ID" ] && [ -n "$DATA_POOL_PG_NUM" ] \
    || { err "failed to resolve RGW data pool id/pg_num"; exit 1; }


############################################################################
info "=== Step 15: verify osdtrace output ==="
verify_osdtrace_rgw_output \
    "$OSDTRACE_LOG" "$DATA_POOL_ID" "$MAX_OSD_ID" "$DATA_POOL_PG_NUM" "$MIN_OSD_ROWS"


############################################################################
info "=== Step 16: verify radostrace output ==="
verify_radostrace_rgw_output \
    "$RADOSTRACE_LOG" "$MAX_OSD_ID" "$MIN_RGW_ROWS"


############################################################################
info "=== Test Summary (cephadm + $CEPH_RELEASE) ==="
info "✓ cluster bootstrapped via cephadm using $CEPH_IMG"
info "✓ 3 OSDs deployed, 1 RGW serving on port 8080"
info "✓ S3 workload (PUT + GET on testbucket) drove the cluster for ~${TRACE_SECONDS}s"
info "✓ osdtrace traced OSD PID $OSD_PID; row-count + per-pool checks passed"
info "✓ radostrace traced radosgw PID $RGW_PID; row-count + W/R diversity checks passed"
exit 0
