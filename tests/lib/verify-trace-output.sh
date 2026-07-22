#!/bin/bash
#
# Generic verifiers for the textual output produced by osdtrace and radostrace.
# Sourced by:
#   - tests/functional-test-microceph.sh
#   - tests/functional-test-embedded-dwarf.sh
#
# Design
# ------
# Each verifier reads its log once and parses every data row into a bash
# associative array (the per-row "dict") whose keys are named field names
# (pid, client, tid, pool, pg, acting, wr, size, latency, object, …).  All
# field-level checks then read named keys from that dict — `${row[size]}`,
# `${row[wr]}` — instead of positional awk fields.  Aggregate checks
# (row count, W/R diversity, size anchor) run after the row loop.
#
# Each verifier returns non-zero on the first failure; the caller's `set -e`
# stops the test.  Both rely on info()/err() from tests/lib/log.sh, which
# the caller is expected to have sourced already.

# Upper bound on per-op latency (µs).  Anything bigger than 100 s almost
# certainly means a timestamp went backwards or the units field is broken.
TRACE_MAX_LATENCY_US=100000000

# rbd bench --io-size used by the functional tests' workload (2 MiB).
# At least one radostrace row must report this exact length — anchors the
# size field to a known constant from the workload, which catches
# endianness/unit/cast regressions in the BPF length extraction.  Random
# 2 MiB IO means most data rows report this size; metadata ops (header
# reads, …) report other sizes, which is why the check is "at least one
# row" rather than "all rows".
TRACE_EXPECTED_IO_SIZE=2097152


# _osdtrace_rows <log>
#
# Stream typed, pipe-separated osdtrace data rows to stdout.  The first
# field is the op-type discriminator (op_r / subop_w / op_w); the
# remaining fields are the op-type's full schema, in printf order.
#
# Schemas (mirror the three print_op_* functions in src/osdtrace.cc):
#
#   op_r    | osd | pool | pg | size | client | tid
#           | throttle_lat | recv_lat | dispatch_lat | queue_lat | osd_lat
#           | bluestore_lat | op_lat | object
#
#   subop_w | osd | pool | pg | size | client | tid
#           | throttle_lat | recv_lat | dispatch_lat | queue_lat | osd_lat
#           | bluestore_lat | prepare_lat | aio_wait_lat | seq_wait_lat
#           | kv_commit_lat | subop_lat | object
#
#   op_w    | osd | pool | pg | size | client | tid
#           | throttle_lat | recv_lat | dispatch_lat | queue_lat | osd_lat
#           | peer0_id | peer0_lat | peer1_id | peer1_lat
#           | bluestore_lat | prepare_lat | aio_wait_lat | seq_wait_lat
#           | kv_commit_lat | op_lat | object
#
# The trailing object field is "-" when the trace could not capture the
# object name (the relevant capture point was not reached, or the DWARF data
# predates object-name support). Whitespace, control bytes, and percent signs
# in captured names are percent-encoded so each object remains one field.
#
# Rejection of malformed/truncated rows is critical: a SIGKILL hitting
# osdtrace mid-printf can leave a row whose tail is the underflowed
# peer-latency token (`(-1, 18446743169577026)]`), and a naive `$NF + 0`
# verifier mistakes that for the total op_lat.  This parser instead
# matches each op type by exact NF AND by literal field-name landmarks
# (e.g. `$24 == "op_lat"` for op_r, `$22 == "peers"` + `$39 == "op_lat"`
# for op_w).  Truncated rows fail at least one landmark and are dropped.
# Same logic drops rows with the `[delayed%d ... ]` continuation tokens
# appended (their NF is inflated past the expected count).
_osdtrace_rows() {
    # The "prev" buffer + END (no flush of prev) makes the LAST data row
    # the parser would otherwise emit get dropped.  Defense-in-depth on
    # top of the NF/landmark check: if SIGKILL hits osdtrace mid-printf
    # at a buffer-flush boundary (libc splitting a large stdio flush
    # across multiple write() syscalls), the byte-truncation can land
    # somewhere the strict NF/landmark check still happens to accept.
    # Skipping the last emit closes that corner.  Cost: one good row per
    # trace, against thousands captured.
    awk '
        function num(s,   _t) { _t = s; gsub(/[^0-9-]/, "", _t); return _t + 0 }
        function flush_pending() { if (prev != "") { print prev; prev = "" } }

        $1 == "osd" && $3 == "pg" && \
        $2 ~ /^-?[0-9]+$/ && \
        $4 ~ /^[0-9]+\.[0-9a-fA-F]+$/ {
            split($4, pg, ".")
            op = $5
            candidate = ""
            if (op == "op_r" && NF == 27 && \
                $6 == "size" && $24 == "op_lat" && $26 == "object") {
                candidate = sprintf("op_r|%d|%s|%s|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%s", \
                    $2, pg[1], pg[2], \
                    $7, $9, $11, \
                    $13, $15, $17, $19, $21, \
                    $23, $25, $27)
            } else if (op == "subop_w" && NF == 37 && \
                       $22 == "bluestore_lat" && $24 == "(prepare" && \
                       $34 == "subop_lat" && $36 == "object") {
                candidate = sprintf("subop_w|%d|%s|%s|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%s", \
                    $2, pg[1], pg[2], \
                    $7, $9, $11, \
                    $13, $15, $17, $19, $21, \
                    $23, $25, $27, $31, num($33), $35, $37)
            } else if (op == "op_w" && NF == 42 && \
                       $22 == "peers" && $27 == "bluestore_lat" && \
                       $29 == "(prepare" && $39 == "op_lat" && \
                       $41 == "object") {
                candidate = sprintf("op_w|%d|%s|%s|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%s", \
                    $2, pg[1], pg[2], \
                    $7, $9, $11, \
                    $13, $15, $17, $19, $21, \
                    num($23), num($24), num($25), num($26), \
                    $28, $30, $32, $36, num($38), $40, $42)
            }
            # else: row was truncated, has [delayed...] suffix, or printed
            #       an op type we do not parse.  Dropped silently.
            if (candidate != "") {
                flush_pending()
                prev = candidate
            }
        }
        # END deliberately omitted: prev holds the last data row the
        # parser would have emitted; not flushing it here drops it.
    ' "$1"
}


# _radostrace_rows <log>
#
# Stream pipe-separated radostrace data rows to stdout, one per line:
#   pid|client|tid|pool|pg|acting|wr|size|latency|object
# Data rows start with a numeric PID (the traced process's PID).  Predicate
# `$1 ~ /^[0-9]+$/ && NF >= 10` rejects the header line ("pid client … "),
# status messages, tool log noise, and — importantly — any truncated tail
# record left behind when SIGKILL hits radostrace mid-printf (after the
# latency field but before object_name).  Numeric coercion on $8/$9
# guards against the same kind of partial-write artifact appearing in
# the size/latency fields.
_radostrace_rows() {
    # Drop the last data row.  SIGKILL/SIGTERM of the writer can leave
    # the file's tail mid-printf (e.g. an `rbd_data.<hex>.<seq>` object
    # name truncated to just `rbd`), and the NF >= 10 predicate is
    # loose enough to admit those byte-truncated rows.  Buffering the
    # latest match in `prev` and not flushing it at END drops exactly
    # the one potentially-malformed row; previously-completed write()
    # syscalls already landed atomically, so every earlier match is
    # safe.  Cost: one good row per trace among thousands.
    awk '
        function flush_pending() { if (prev != "") { print prev; prev = "" } }
        $1 ~ /^[0-9]+$/ && NF >= 10 {
            flush_pending()
            prev = $1 "|" $2 "|" $3 "|" $4 "|" $5 "|" $6 "|" $7 "|" \
                   ($8 + 0) "|" ($9 + 0) "|" $10
        }
        # END deliberately omitted: prev holds the last data row; not
        # flushing it here drops it.
    ' "$1"
}


# verify_osdtrace_output <log> <test_pool_id> <max_osd_id> <pg_num> <min_rows>
#
# The tight per-row loop is wrapped so that shell xtrace (set -x) is
# silenced during it: under CI the test scripts run with set -x for
# orchestration visibility, but tracing ~15 commands per row over tens of
# thousands of rows drowns the runner's log pipe and effectively hangs the
# job.  xtrace state is restored before return so the caller keeps tracing.
verify_osdtrace_output() {
    local _xtrace=0
    case $- in *x*) _xtrace=1; set +x;; esac

    _verify_osdtrace_output_impl "$@"
    local rc=$?

    (( _xtrace == 1 )) && set -x
    return $rc
}

# Per-row invariants shared across all three op types:
#   - osd_id within [0, max_osd_id]
#   - total op_lat (or subop_lat) within TRACE_MAX_LATENCY_US
# Helpers read $row (associative array) and $max_osd_id from the caller's
# scope; bash dynamic-scoped locals make that work.
_osdtrace_check_common() {
    if (( row[osd_id] < 0 || row[osd_id] > max_osd_id )); then
        err "Found OSD id ${row[osd_id]} outside [0, $max_osd_id] (op=${row[op]} pool=${row[pool]} tid=${row[tid]})"
        return 1
    fi
    if (( row[op_lat] > TRACE_MAX_LATENCY_US )); then
        err "Found op_lat ${row[op_lat]} µs > $TRACE_MAX_LATENCY_US µs in osdtrace output (op=${row[op]} osd=${row[osd_id]} pool=${row[pool]} tid=${row[tid]})"
        return 1
    fi
}

# Strict invariant: every named sub-latency field must be <= total op_lat.
# A sub-latency exceeding the total signals an unsigned-underflow in the
# BPF timestamp subtraction (end < start), which has been seen on rare
# events; without this check the underflowed value just looks like a
# huge µs number and quietly poisons downstream analysis.
_osdtrace_check_sublatencies() {
    local field
    for field in "$@"; do
        if (( row[$field] > row[op_lat] )); then
            err "Sub-latency ${field}=${row[$field]} µs > op_lat=${row[op_lat]} µs (op=${row[op]} osd=${row[osd_id]} pool=${row[pool]} tid=${row[tid]})"
            return 1
        fi
    done
}

# Optional per-peer check for op_w only.  Peer slot is -1 when the pool's
# replication factor leaves that slot unused; the corresponding peer_lat
# is uninitialised garbage and must be skipped.
_osdtrace_check_peer() {
    local id_field=$1 lat_field=$2
    if (( row[$id_field] == -1 )); then
        return 0
    fi
    if (( row[$id_field] < 0 || row[$id_field] > max_osd_id )); then
        err "Peer OSD id ${row[$id_field]} outside [0, $max_osd_id] (op_w osd=${row[osd_id]} pool=${row[pool]} tid=${row[tid]})"
        return 1
    fi
    if (( row[$lat_field] > row[op_lat] )); then
        err "Peer latency ${lat_field}=${row[$lat_field]} µs > op_lat=${row[op_lat]} µs (op_w osd=${row[osd_id]} peer=${row[$id_field]} tid=${row[tid]})"
        return 1
    fi
}

_verify_osdtrace_output_impl() {
    local log=$1
    local test_pool_id=$2
    local max_osd_id=$3
    local pg_num=$4
    local min_rows=$5

    local pool_rows=0
    local op_r_total=0 subop_w_total=0 op_w_total=0
    local op_r_pool=0  subop_w_pool=0  op_w_pool=0
    local named_objects=0
    local -A row
    local line op_type _
    local pg_dec

    # Per-op-type field lists, used to populate $row from the parser
    # output and to enumerate sub-latency fields for the strict bound.
    local -a OP_R_SUBLATS=(throttle_lat recv_lat dispatch_lat queue_lat osd_lat bluestore_lat)
    local -a SUBOP_W_SUBLATS=(throttle_lat recv_lat dispatch_lat queue_lat osd_lat bluestore_lat prepare_lat aio_wait_lat seq_wait_lat kv_commit_lat)
    local -a OP_W_SUBLATS=(throttle_lat recv_lat dispatch_lat queue_lat osd_lat bluestore_lat prepare_lat aio_wait_lat seq_wait_lat kv_commit_lat)

    while IFS= read -r line; do
        [ -z "$line" ] && continue
        op_type=${line%%|*}
        row=( [op]="$op_type" )

        case "$op_type" in
            op_r)
                IFS='|' read -r _ row[osd_id] row[pool] row[pg] \
                    row[size] row[client] row[tid] \
                    row[throttle_lat] row[recv_lat] row[dispatch_lat] \
                    row[queue_lat] row[osd_lat] \
                    row[bluestore_lat] row[op_lat] row[object] <<< "$line"
                op_r_total=$((op_r_total + 1))
                _osdtrace_check_common || return 1
                _osdtrace_check_sublatencies "${OP_R_SUBLATS[@]}" || return 1
                ;;
            subop_w)
                IFS='|' read -r _ row[osd_id] row[pool] row[pg] \
                    row[size] row[client] row[tid] \
                    row[throttle_lat] row[recv_lat] row[dispatch_lat] \
                    row[queue_lat] row[osd_lat] \
                    row[bluestore_lat] row[prepare_lat] row[aio_wait_lat] \
                    row[seq_wait_lat] row[kv_commit_lat] row[op_lat] \
                    row[object] <<< "$line"
                subop_w_total=$((subop_w_total + 1))
                _osdtrace_check_common || return 1
                _osdtrace_check_sublatencies "${SUBOP_W_SUBLATS[@]}" || return 1
                ;;
            op_w)
                IFS='|' read -r _ row[osd_id] row[pool] row[pg] \
                    row[size] row[client] row[tid] \
                    row[throttle_lat] row[recv_lat] row[dispatch_lat] \
                    row[queue_lat] row[osd_lat] \
                    row[peer0_id] row[peer0_lat] row[peer1_id] row[peer1_lat] \
                    row[bluestore_lat] row[prepare_lat] row[aio_wait_lat] \
                    row[seq_wait_lat] row[kv_commit_lat] row[op_lat] \
                    row[object] <<< "$line"
                op_w_total=$((op_w_total + 1))
                _osdtrace_check_common || return 1
                _osdtrace_check_sublatencies "${OP_W_SUBLATS[@]}" || return 1
                _osdtrace_check_peer peer0_id peer0_lat || return 1
                _osdtrace_check_peer peer1_id peer1_lat || return 1
                ;;
            *)
                continue  # parser only emits the three above
                ;;
        esac

        # Object names are best-effort: "-" is legal when the DWARF data
        # predates object-name support, so only count real names for the
        # summary line instead of failing on "-".
        if [[ "${row[object]:-"-"}" != "-" ]]; then
            named_objects=$((named_objects + 1))
        fi

        # Per-pool checks (PG range; per-pool row count): only count rows
        # that hit the workload's test_pool.  osdtrace also captures
        # internal pool traffic (.mgr/.osd/etc.) whose pg_num differs.
        if [ "${row[pool]}" = "$test_pool_id" ]; then
            pool_rows=$((pool_rows + 1))
            case "$op_type" in
                op_r)    op_r_pool=$((op_r_pool + 1)) ;;
                subop_w) subop_w_pool=$((subop_w_pool + 1)) ;;
                op_w)    op_w_pool=$((op_w_pool + 1)) ;;
            esac

            # PG index within pg_num.  osdtrace prints PG in hex
            # (std::hex on op.pg.m_seed) without an `0x` prefix, so plain
            # decimal parsing would silently accept any hex letters as 0.
            # Convert with bash's `$((16#…))`.
            pg_dec=$((16#${row[pg]}))
            if (( pg_dec < 0 || pg_dec >= pg_num )); then
                err "Found PG ${row[pg]} (decimal $pg_dec) outside expected range [0, $pg_num) in osdtrace output (op=${row[op]} osd=${row[osd_id]} tid=${row[tid]})"
                return 1
            fi
        fi
    done < <(_osdtrace_rows "$log")

    info "osdtrace per-op-type totals: op_r=$op_r_total subop_w=$subop_w_total op_w=$op_w_total (rows with object name: $named_objects)"
    info "osdtrace per-op-type rows on test_pool ($test_pool_id): op_r=$op_r_pool subop_w=$subop_w_pool op_w=$op_w_pool (total $pool_rows)"
    if (( pool_rows < min_rows )); then
        err "osdtrace did not capture enough trace data for test_pool (expected >= $min_rows rows, got $pool_rows)"
        return 1
    fi

    info "✓ All osdtrace output fields validated successfully"
}


# verify_radostrace_output <log> <test_pool_id> <max_osd_id> <min_rows>
#
# All invariants below are anchored to the rbd-bench PID radostrace is
# attached to.  The workload (microceph.rbd bench --io-type=readwrite
# --io-pattern=rand --io-size=2M) issues both directions through librbd
# → librados → Objecter, so the W+R diversity check is meaningful.  Two
# settings make reads actually reach RADOS rather than getting satisfied
# locally: the test creates the image with --image-feature layering (no
# object-map → no client-side short-circuit on unallocated regions), and
# microceph_disable_rbd_cache turns off librbd's client cache so freshly
# written data isn't read back from local memory.
#
# Wrapped the same way as verify_osdtrace_output to silence xtrace during
# the per-row loop — see that function's header for why.
verify_radostrace_output() {
    local _xtrace=0
    case $- in *x*) _xtrace=1; set +x;; esac

    _verify_radostrace_output_impl "$@"
    local rc=$?

    (( _xtrace == 1 )) && set -x
    return $rc
}

_verify_radostrace_output_impl() {
    local log=$1
    local test_pool_id=$2
    local max_osd_id=$3
    local min_rows=$4

    local total=0
    local saw_w=0 saw_r=0 saw_bench_size=0
    local -A row
    local pid client tid pool pg acting wr size latency object
    local acting_inner osd_id_str osd_id

    while IFS='|' read -r pid client tid pool pg acting wr size latency object; do
        [ -z "$pid" ] && continue

        # Per-row dict.  All subsequent checks read fields by name.
        row=(
            [pid]="$pid"
            [client]="$client"
            [tid]="$tid"
            [pool]="$pool"
            [pg]="$pg"
            [acting]="$acting"
            [wr]="$wr"
            [size]="$size"
            [latency]="$latency"
            [object]="$object"
        )
        total=$((total + 1))

        # 1. Pool id matches test_pool.
        if [ "${row[pool]}" != "$test_pool_id" ]; then
            err "Unexpected pool id ${row[pool]} in radostrace output (expected $test_pool_id, tid=${row[tid]})"
            return 1
        fi

        # 2. WR flag is W or R.  Tracking diversity in the same step so we
        #    don't re-traverse the rows after the loop.
        case "${row[wr]}" in
            W) saw_w=1 ;;
            R) saw_r=1 ;;
            *) err "Invalid WR flag '${row[wr]}' in radostrace output (expected W or R, tid=${row[tid]})"
               return 1 ;;
        esac

        # 3. Acting-set OSD ids within 0..max_osd_id.  Acting is a
        #    comma-separated list inside square brackets, e.g. "[1,0,2]".
        acting_inner=${row[acting]#\[}
        acting_inner=${acting_inner%\]}
        local IFS_save=$IFS
        IFS=','
        # shellcheck disable=SC2086  # intentional word-split on commas
        for osd_id_str in $acting_inner; do
            osd_id=$((osd_id_str))
            if (( osd_id < 0 || osd_id > max_osd_id )); then
                IFS=$IFS_save
                err "OSD id $osd_id in acting set ${row[acting]} outside valid range [0, $max_osd_id] (tid=${row[tid]})"
                return 1
            fi
        done
        IFS=$IFS_save

        # 4. Latency upper bound.  Latency was numeric-coerced in
        #    _radostrace_rows.  Zero latency is permitted: a small IO can
        #    complete in sub-microsecond on a local loopback cluster, and
        #    (finish_stamp - sent_stamp) / 1000 truncates to 0 for those
        #    ops.  That's a legitimate measurement, not a bug.
        if (( row[latency] > TRACE_MAX_LATENCY_US )); then
            err "Found latency ${row[latency]} µs > $TRACE_MAX_LATENCY_US µs in radostrace output (tid=${row[tid]})"
            return 1
        fi

        # 5. Object name matches the workload's expected prefix.  All
        #    librbd traffic from the rbd-bench workload targets `rbd_*`
        #    objects (rbd_data.*, rbd_header.*, rbd_id.*, rbd_directory).
        #    Catches garbled object-name extraction in the BPF helper.
        #    Truncated tail records (where radostrace was killed before
        #    printing the object name) are filtered upstream by the NF >=
        #    10 predicate in _radostrace_rows.
        if [[ ! "${row[object]}" =~ ^rbd_ ]]; then
            err "Unexpected object name '${row[object]}' in radostrace output (expected rbd_*, tid=${row[tid]} wr=${row[wr]})"
            return 1
        fi

        # 6. Track whether any row hit the workload's fio --bs (4 KiB).
        #    Confirms the size field carries the workload's known constant.
        if (( row[size] == TRACE_EXPECTED_IO_SIZE )); then
            saw_bench_size=1
        fi
    done < <(_radostrace_rows "$log")

    # 7. Aggregate: row count.
    info "radostrace captured $total trace rows"
    if (( total < min_rows )); then
        err "radostrace did not capture enough data (expected >= $min_rows rows, got $total)"
        return 1
    fi

    # 8. Both W and R must appear — workload (rbd bench --io-type=readwrite
    #    --rw-mix-read=50) issues both directions.  Catches regressions
    #    where one direction is silently dropped (e.g. a uretprobe missing
    #    on the read path).
    if (( saw_w == 0 )); then
        err "radostrace output has no 'W' rows but workload issued writes"
        return 1
    fi
    if (( saw_r == 0 )); then
        err "radostrace output has no 'R' rows but workload issued reads"
        return 1
    fi

    # 9. At least one row reported the bench --io-size (4 KiB).  Anchors
    #    the size field to a known workload constant.
    if (( saw_bench_size == 0 )); then
        err "radostrace output has no row with size=$TRACE_EXPECTED_IO_SIZE (rbd bench --io-size)"
        return 1
    fi

    info "✓ All radostrace output fields validated successfully"
}


# verify_osdtrace_targets_only <log> <target_osd_id> [target_osd_id ...]
#
# Anchors --id semantics: assert the set of distinct osd_id values appearing
# in <log>'s data rows is a subset of the given targets.  Reuses
# _osdtrace_rows so it shares the same NF/landmark-based row parser as the
# main verifier (truncated tail rows are filtered upstream).
#
# Fails if:
#   - any data row carries an osd_id outside the target set (proves uprobes
#     attached to a process the user didn't ask for), or
#   - no data rows were captured at all (proves the --id resolution → attach
#     path produced *something*; the looser min_rows check is left to
#     verify_osdtrace_output).
verify_osdtrace_targets_only() {
    local log=$1
    shift
    local -A want=()
    local id
    for id in "$@"; do
        want[$id]=1
    done

    local total=0
    local op_type osd_id _rest
    while IFS='|' read -r op_type osd_id _rest; do
        [ -z "$op_type" ] && continue
        total=$((total + 1))
        if [ -z "${want[$osd_id]:-}" ]; then
            err "osdtrace row carries osd_id=$osd_id, expected one of: $* (log=$log)"
            return 1
        fi
    done < <(_osdtrace_rows "$log")

    if (( total == 0 )); then
        err "osdtrace log $log has zero data rows; --id resolution may have failed silently"
        return 1
    fi

    info "✓ osdtrace targets-only check passed ($total rows, all in {$*})"
}


# verify_osdtrace_rgw_output <log> <data_pool_id> <max_osd_id> <data_pool_pg_num> <min_rows>
#
# Variant of verify_osdtrace_output for RGW-driven workloads (S3 PUT/GET via
# `radosgw`).  Same per-row invariants -- OSD id range, latency upper bound,
# PG-within-pg_num -- but anchored to the data pool the RGW writes object
# payloads into (typically `default.rgw.buckets.data`) rather than a single
# user-created pool.  RGW also generates traffic to several internal pools
# (.rgw.meta, .rgw.buckets.index, .rgw.log, ...); those rows are ignored
# for the per-pool checks since their pg_num values differ.
verify_osdtrace_rgw_output() {
    # Implementation re-uses the rbd-bench verifier's row loop; the per-pool
    # filter already restricts the PG check + row count to the named pool,
    # which is exactly the semantics we want for RGW.
    verify_osdtrace_output "$@"
}


# verify_radostrace_rgw_output <log> <max_osd_id> <min_rows>
#
# Variant of verify_radostrace_output for RGW-driven workloads.  Drops three
# rbd-bench-specific checks that do not apply to RGW traffic:
#   - pool id pin: RGW sprays across .rgw.meta / .rgw.buckets.index /
#     .rgw.buckets.data / .rgw.log; there is no single canonical pool.
#   - `^rbd_` object name prefix: RGW objects are
#     `<bucket-marker>_<oid>` / `_shadow_.<…>` / `meta.head:user.<…>` etc.
#   - 2 MiB IO size anchor: the S3 PUT workload uses randomised sizes.
#
# Kept (pool-agnostic) invariants:
#   - row count >= min_rows
#   - WR flag is W or R, both directions observed
#   - every OSD id in the acting set within [0, max_osd_id]
#   - latency <= TRACE_MAX_LATENCY_US
verify_radostrace_rgw_output() {
    local _xtrace=0
    case $- in *x*) _xtrace=1; set +x;; esac

    _verify_radostrace_rgw_output_impl "$@"
    local rc=$?

    (( _xtrace == 1 )) && set -x
    return $rc
}

_verify_radostrace_rgw_output_impl() {
    local log=$1
    local max_osd_id=$2
    local min_rows=$3

    local total=0
    local saw_w=0 saw_r=0
    local -A row
    local pid client tid pool pg acting wr size latency object
    local acting_inner osd_id_str osd_id

    while IFS='|' read -r pid client tid pool pg acting wr size latency object; do
        [ -z "$pid" ] && continue

        row=(
            [pid]="$pid"
            [client]="$client"
            [tid]="$tid"
            [pool]="$pool"
            [pg]="$pg"
            [acting]="$acting"
            [wr]="$wr"
            [size]="$size"
            [latency]="$latency"
            [object]="$object"
        )
        total=$((total + 1))

        case "${row[wr]}" in
            W) saw_w=1 ;;
            R) saw_r=1 ;;
            *) err "Invalid WR flag '${row[wr]}' in radostrace output (expected W or R, tid=${row[tid]})"
               return 1 ;;
        esac

        acting_inner=${row[acting]#\[}
        acting_inner=${acting_inner%\]}
        local IFS_save=$IFS
        IFS=','
        # shellcheck disable=SC2086  # intentional word-split on commas
        for osd_id_str in $acting_inner; do
            osd_id=$((osd_id_str))
            if (( osd_id < 0 || osd_id > max_osd_id )); then
                IFS=$IFS_save
                err "OSD id $osd_id in acting set ${row[acting]} outside valid range [0, $max_osd_id] (tid=${row[tid]})"
                return 1
            fi
        done
        IFS=$IFS_save

        if (( row[latency] > TRACE_MAX_LATENCY_US )); then
            err "Found latency ${row[latency]} µs > $TRACE_MAX_LATENCY_US µs in radostrace output (tid=${row[tid]})"
            return 1
        fi
    done < <(_radostrace_rows "$log")

    info "radostrace captured $total trace rows from RGW workload"
    if (( total < min_rows )); then
        err "radostrace did not capture enough data (expected >= $min_rows rows, got $total)"
        return 1
    fi

    if (( saw_w == 0 )); then
        err "radostrace output has no 'W' rows but workload issued PUTs"
        return 1
    fi
    if (( saw_r == 0 )); then
        err "radostrace output has no 'R' rows but workload issued GETs"
        return 1
    fi

    info "✓ All radostrace output fields validated successfully"
}
