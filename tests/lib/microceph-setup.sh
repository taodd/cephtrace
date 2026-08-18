#!/bin/bash

# Shared helpers for tests that need a single-node MicroCeph cluster.
# Source from a test script: source "$SCRIPT_DIR/lib/microceph-setup.sh"

_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=log.sh
source "$_LIB_DIR/log.sh"

# Install MicroCeph snap (if missing), bootstrap a single-node cluster,
# add loop-backed OSDs (if fewer than requested), and wait until the
# cluster reports HEALTH_OK or HEALTH_WARN.
#
# Args:
#   $1  osd_count           number of OSDs to ensure (default 3)
#   $2  osd_size            per-OSD size as accepted by `microceph disk add` (default 1G)
#   $3  health_timeout_sec  max seconds to wait for healthy state (default 120)
#
# Returns 0 on healthy cluster, 1 on health-wait timeout.
microceph_setup_single_node() {
    local osd_count="${1:-3}"
    local osd_size="${2:-1G}"
    local health_timeout="${3:-120}"

    if ! snap list 2>/dev/null | grep -q microceph; then
        info "Installing MicroCeph snap..."
        snap install microceph
        snap refresh --hold microceph
    else
        info "MicroCeph snap already installed"
    fi

    if ! microceph cluster list 2>/dev/null | grep -q "$(hostname)"; then
        info "Bootstrapping MicroCeph cluster..."
        microceph cluster bootstrap
    else
        info "MicroCeph cluster already bootstrapped"
    fi

    local current_osds
    current_osds=$(microceph.ceph osd stat | grep -oP '\d+(?= osds:)' || echo "0")
    if [ "$current_osds" -lt "$osd_count" ]; then
        info "Adding $osd_count loop-backed OSDs (${osd_size} each)..."
        microceph disk add "loop,${osd_size},${osd_count}"
    else
        info "Already have $current_osds OSDs (target $osd_count)"
    fi

    # Wait until the cluster is genuinely ready to accept traffic.  A fresh
    # bootstrap reports HEALTH_WARN immediately (because of TOO_FEW_OSDS,
    # mon_warn_on_insecure_global_id_reclaim, etc.), so grepping for
    # HEALTH_(OK|WARN) alone returns "ready" with 0 OSDs up -- and the test
    # then attaches osdtrace to a ceph-osd PID that exits seconds later when
    # the cluster's first pool-create races a still-booting OSD.
    #
    # Require: at least one mon in quorum, the requested number of OSDs
    # both up AND in, and the overall health string OK or WARN.
    info "Waiting for $osd_count OSDs up+in and mon quorum (timeout ${health_timeout}s)..."
    local elapsed=0
    while [ "$elapsed" -lt "$health_timeout" ]; do
        local status_json
        status_json=$(microceph.ceph status --format=json 2>/dev/null) || true
        # JSON via stdin, not spliced into the python source: escapes such as
        # the \n in progress_events[].message would become real control
        # characters inside the string literal and break json.loads().
        if [ -n "$status_json" ] && printf '%s' "$status_json" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(2)
health = d.get('health', {}).get('status', '')
quorum = len(d.get('quorum_names', []))
osdmap = d.get('osdmap', {})
ups = osdmap.get('num_up_osds', 0)
ins = osdmap.get('num_in_osds', 0)
need = int('$osd_count')
sys.exit(0 if (health in ('HEALTH_OK', 'HEALTH_WARN')
               and quorum >= 1
               and ups >= need
               and ins >= need)
         else 1)
"; then
            info "Cluster ready: ${osd_count} OSDs up+in (${elapsed}s)"
            return 0
        fi
        sleep 5
        elapsed=$((elapsed + 5))
    done
    err "Cluster did not become ready (${osd_count} OSDs up+in) within ${health_timeout}s"
    microceph.ceph status 2>&1 | tail -20 || true
    return 1
}

# Disable librbd client-side cache in microceph's snap-internal ceph.conf.
# Without this, reads of recently-written data are satisfied locally inside
# librbd's cache and never reach RADOS — so radostrace's uprobes on
# Objecter::_send_op / _finish_op never fire on the read path.  The image
# also needs `--image-feature layering` (no object-map) for reads of
# unallocated regions to reach RADOS; the two together close all the
# client-side short-circuits we know of.
microceph_disable_rbd_cache() {
    local conf=/var/snap/microceph/current/conf/ceph.conf

    if [ ! -w "$conf" ]; then
        err "microceph conf $conf not writable (need root?)"
        return 1
    fi

    if grep -q "^[[:space:]]*rbd_cache" "$conf"; then
        info "rbd_cache already configured in $conf"
        return 0
    fi

    info "Appending rbd_cache=false to $conf (trace visibility for reads)"
    if ! grep -q "^[[:space:]]*\[client\]" "$conf"; then
        printf '\n[client]\n' >> "$conf"
    fi
    sed -i '/^\[client\]/a rbd_cache = false' "$conf"
}
