#!/usr/bin/env python3
"""
cephtrace_report - a one-screen visual summary of radostrace / osdtrace output.

This is the "is it slow, what's slow, where's the time going" glance: it draws
bar charts and a latency histogram so the shape of a capture is understandable
at sight, with no flags to remember.

It complements - it does not replace - the two detailed analyzers:
  * analyze_osdtrace_output.py   fio-style percentile tables, per-stage
                                 contribution (-i), per-OSD/field filtering
  * analyze_radostrace_output.py iterative culprit-OSD ranking mapped to hosts

To avoid a second, divergent parser, the osdtrace path reuses
analyze_osdtrace_output.parse_line, and the radostrace path reuses
analyze_radostrace_output.detect_file_format and the same column layout.

Usage:
    radostrace -t 30 > rados.log && ./tools/cephtrace_report.py rados.log
    sudo ./osdtrace --id 0 -t 30 | ./tools/cephtrace_report.py

    # write a self-contained, interactive HTML report instead of terminal text
    ./tools/cephtrace_report.py --html report.html osd.log
"""
import csv
import json
import os
import re
import shutil
import sys
from collections import Counter, defaultdict

# Reuse the existing, battle-tested parsers from the sibling analyzers rather
# than maintain a second one that could drift.  They live in this directory,
# so put it on the path first; pylint can't follow that runtime edit, hence
# the targeted disables.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# pylint: disable=wrong-import-position,import-error
from analyze_osdtrace_output import parse_line as parse_osd_line  # noqa: E402
from analyze_radostrace_output import detect_file_format  # noqa: E402
# pylint: enable=wrong-import-position,import-error

# 1/8th-width cells give smooth, sub-character-resolution bars.
_CELLS = " ▏▎▍▌▋▊▉█"

# Log-scale latency buckets (microseconds), shared by the terminal histogram
# and the HTML report so both tell the same story.
_HIST_EDGES = [250, 500, 1000, 2000, 4000, 8000, 16000, 32000, 64000, 1e18]
_HIST_NAMES = ["<250us", "<500us", "<1ms", "<2ms", "<4ms", "<8ms", "<16ms",
               "<32ms", "<64ms", ">=64ms"]


def _bucketize(lats):
    """Count latencies into the shared log-scale buckets."""
    buckets = [0] * len(_HIST_EDGES)
    for value in lats:
        for i, edge in enumerate(_HIST_EDGES):
            if value < edge:
                buckets[i] += 1
                break
    return buckets


def _bar(frac, width):
    """Render a proportional unicode bar padded to ``width`` columns."""
    frac = 0.0 if frac < 0 else 1.0 if frac > 1 else frac
    full = int(frac * width)
    rem = int(round((frac * width - full) * 8))
    return ("█" * full + (_CELLS[rem] if rem else "")).ljust(width)


def _pct(sorted_vals, percentile):
    """Linear-interpolated percentile of an already-sorted list."""
    if not sorted_vals:
        return 0
    pos = (len(sorted_vals) - 1) * percentile / 100.0
    low = int(pos)
    if low + 1 >= len(sorted_vals):
        return sorted_vals[low]
    return sorted_vals[low] + (sorted_vals[low + 1] - sorted_vals[low]) * (
        pos - low)


def _us(value):
    """Human-readable latency from a microsecond value."""
    value = float(value)
    if value < 1000:
        return f"{value:.0f}us"
    if value < 1_000_000:
        return f"{value / 1000:.1f}ms"
    return f"{value / 1_000_000:.2f}s"


def _hsize(value):
    """Human-readable byte size."""
    value = float(value)
    for unit in ("B", "K", "M", "G"):
        if value < 1024:
            fmt = "{:.0f}{}" if unit == "B" else "{:.1f}{}"
            return fmt.format(value, unit)
        value /= 1024
    return f"{value:.1f}T"


def _heading(text):
    """Print a section heading, bold only when writing to a terminal."""
    print(f"\n\033[1m{text}\033[0m" if sys.stdout.isatty() else f"\n{text}")


def _bar_width(term_width):
    """Bar column count that leaves room for labels at this terminal width."""
    return max(16, min(40, term_width - 34))


def latency_histogram(lats, bar_w, label):
    """Draw a log-scale latency histogram plus a p50/p95/p99/max line.

    The percentile *tables* already live in the analyzers; what they lack is
    the distribution *shape*, which is what this renders.
    """
    buckets = _bucketize(lats)
    ordered = sorted(lats)
    _heading(f"{label} distribution   "
             f"p50 {_us(_pct(ordered, 50))}   p95 {_us(_pct(ordered, 95))}   "
             f"p99 {_us(_pct(ordered, 99))}   max {_us(ordered[-1])}")
    peak = max(buckets) or 1
    for name, count in zip(_HIST_NAMES, buckets):
        if count:
            print(f"    {name:>7}  {_bar(count / peak, bar_w)} {count}")


# ---------------------------------------------------------------------------
# osdtrace
# ---------------------------------------------------------------------------

def _osd_where_time_goes(rows, bar_w):
    """Aggregate share of total latency per stage (stages overlap, so the
    shares need not sum to 100% - this shows which stage dominates)."""
    total = sum(r["lat"] for r in rows) or 1
    stage_of = {
        "messenger": lambda r: (r["throttle_lat"] + r["recv_lat"]
                                + r["dispatch_lat"]),
        "queue": lambda r: r["queue_lat"],
        "osd": lambda r: r["osd_lat"],
        "bluestore": lambda r: r["bluestore_lat"],
    }
    _heading("where the time goes   (share of total latency, "
             f"avg {_us(total / len(rows))}/op)")
    for stage, func in stage_of.items():
        frac = sum(func(r) for r in rows) / total
        print(f"    {stage:>10}  {_bar(frac, bar_w)} {100 * frac:.0f}%")
    kv_commit = sum(r["bluestore_details"].get("kv_commit", 0) for r in rows)
    if kv_commit:
        print(f"     +kv_commit {_bar(kv_commit / total, bar_w)} "
              f"{100 * kv_commit / total:.0f}%  (rocksdb commit)")


def _osd_per_osd_p95(rows, bar_w):
    """Per-OSD p95 latency bars - only meaningful with >1 OSD captured."""
    by_osd = defaultdict(list)
    for row in rows:
        by_osd[row["osd"]].append(row["lat"])
    if len(by_osd) <= 1:
        return
    _heading("per-OSD p95 latency")
    ranked = sorted(by_osd.items(),
                    key=lambda kv: -_pct(sorted(kv[1]), 95))[:8]
    top = _pct(sorted(ranked[0][1]), 95) or 1
    for osd, lats in ranked:
        p95 = _pct(sorted(lats), 95)
        print(f"    osd.{osd:<5} {_bar(p95 / top, bar_w)} "
              f"{_us(p95)}  ({len(lats)} ops)")


def report_osdtrace(rows, width):
    """Print the full osdtrace visual summary."""
    bar_w = _bar_width(width)
    bytype = Counter(r["op"] for r in rows)
    _heading(f"osdtrace summary - {len(rows)} OSD ops")
    print("  " + "   ".join(f"{t} {c}" for t, c in bytype.most_common()))

    _osd_where_time_goes(rows, bar_w)
    latency_histogram([r["lat"] for r in rows], bar_w, "op latency")
    _osd_per_osd_p95(rows, bar_w)

    _heading("slowest ops")
    for row in sorted(rows, key=lambda r: -r["lat"])[:5]:
        print(f"    {_us(row['lat']):>7}  {row['op']:<8} osd.{row['osd']} "
              f"pg {row['pg']} {_hsize(row['size'])}")

    print("\n  -> deeper: ./tools/analyze_osdtrace_output.py <log> "
          "[-i | -f kv_commit | -o <osd>]")


# ---------------------------------------------------------------------------
# radostrace
# ---------------------------------------------------------------------------

# Column layout shared with analyze_radostrace_output.py (space and CSV):
#   0 pid  1 client  2 tid  3 pool  4 pg  5 acting  6 WR  7 size  8 latency
#   9.. object + [ops]
def _parse_radostrace(lines, is_csv):
    """Parse radostrace rows into dicts: wr, size, lat, pool, obj, acting."""
    rows = []
    if is_csv:
        for row in csv.reader(lines):
            if len(row) < 10 or not row[8].isdigit():
                continue
            obj = row[9] + (" " + row[10] if len(row) > 10 and row[10] else "")
            rows.append({"wr": row[6], "size": int(row[7]),
                         "lat": int(row[8]), "pool": row[3], "obj": obj,
                         "acting": [int(x) for x in re.findall(r"\d+",
                                                               row[5])]})
        return rows
    for line in lines:
        if not line.strip() or line.startswith(("Execution", "Version")):
            continue
        parts = line.split()
        if len(parts) < 10 or not parts[8].isdigit():
            continue
        rows.append({"wr": parts[6], "size": int(parts[7]),
                     "lat": int(parts[8]), "pool": parts[3],
                     "obj": " ".join(parts[9:]),
                     "acting": [int(x) for x in re.findall(r"\d+", parts[5])]})
    return rows


def _rados_pools(rows, bar_w):
    """Ops-per-pool bars - only shown for multi-pool captures (RGW etc.)."""
    pools = Counter(r["pool"] for r in rows)
    if len(pools) <= 1:
        return
    _heading("ops per pool")
    pmax = pools.most_common(1)[0][1]
    for pool, count in pools.most_common(6):
        print(f"    pool {pool:<5} {_bar(count / pmax, bar_w)} {count}")


def _rados_slow_osds(rows, bar_w):
    """OSDs in the acting set of the slowest ops - a quick culprit pointer
    (the radostrace analyzer does the full iterative, host-mapped ranking)."""
    cut = max(1, len(rows) // 20)
    slow = sorted(rows, key=lambda r: -r["lat"])[:cut]
    culprit = Counter(osd for r in slow for osd in r["acting"])
    if not culprit:
        return
    _heading(f"OSDs in the acting set of the slowest {cut} ops")
    cmax = culprit.most_common(1)[0][1]
    for osd, count in culprit.most_common(6):
        print(f"    osd.{osd:<5} {_bar(count / cmax, bar_w)} {count}")


def report_radostrace(rows, width):
    """Print the full radostrace visual summary."""
    bar_w = _bar_width(width)
    total = len(rows)
    reads = sum(1 for r in rows if r["wr"] == "R")
    writes = sum(1 for r in rows if r["wr"] == "W")
    _heading(f"radostrace summary - {total} client ops")
    rmax = max(reads, writes) or 1
    print(f"    reads   {reads:>6}  {_bar(reads / rmax, bar_w)} "
          f"{100 * reads // total}%")
    print(f"    writes  {writes:>6}  {_bar(writes / rmax, bar_w)} "
          f"{100 * writes // total}%")

    latency_histogram([r["lat"] for r in rows], bar_w, "latency")
    _rados_pools(rows, bar_w)
    _rados_slow_osds(rows, bar_w)

    _heading("slowest ops")
    for row in sorted(rows, key=lambda r: -r["lat"])[:5]:
        print(f"    {_us(row['lat']):>7}  {row['wr']}  "
              f"{row['obj'][:max(20, width - 18)]}")

    print("\n  -> deeper: ./tools/analyze_radostrace_output.py <log> "
          "<osd_tree> [threshold_us]")


# ---------------------------------------------------------------------------

def _is_osdtrace(lines):
    """True when the input looks like osdtrace ('osd <n> pg ...') output."""
    return any(re.match(r"osd\s+\d+\s+pg\s", ln) for ln in lines)


def _load(lines, is_csv):
    """Parse buffered lines into ('osdtrace'|'radostrace', rows)."""
    if _is_osdtrace(lines):
        rows = [d[0] for d in (parse_osd_line(ln) for ln in lines) if d]
        return "osdtrace", rows
    return "radostrace", _parse_radostrace(lines, is_csv)


# ---------------------------------------------------------------------------
# HTML report (self-contained; aggregates precomputed here, rendered by the
# JS in report_template.html over the embedded JSON payload).
# ---------------------------------------------------------------------------

def _timeline(rows, slices=60):
    """p50/p95 per equal slice of the capture, in arrival order."""
    if len(rows) < slices:
        slices = max(1, len(rows))
    step = len(rows) / slices
    out = []
    for i in range(slices):
        chunk = rows[int(i * step):int((i + 1) * step)]
        lats = sorted(r["lat"] for r in chunk)
        if lats:
            out.append({"p50": round(_pct(lats, 50)),
                        "p95": round(_pct(lats, 95)), "n": len(lats)})
    return out


def _group_stats(groups):
    """Per-group {id, count, p50, p95, max} + per-group histograms."""
    table, hists = [], {}
    for gid, lats in groups.items():
        ordered = sorted(lats)
        table.append({"id": gid, "count": len(ordered),
                      "p50": round(_pct(ordered, 50)),
                      "p95": round(_pct(ordered, 95)), "max": ordered[-1]})
        hists[str(gid)] = _bucketize(ordered)
    table.sort(key=lambda g: -g["p95"])
    return table, hists


def _build_payload(kind, rows):
    """Compact JSON-able aggregates for the HTML template."""
    lats = sorted(r["lat"] for r in rows)
    summary = {"ops": len(rows), "p50": _us(_pct(lats, 50)),
               "p95": _us(_pct(lats, 95)), "p99": _us(_pct(lats, 99)),
               "max": _us(lats[-1])}
    payload = {"kind": kind, "summary": summary,
               "histLabels": _HIST_NAMES,
               "histOverall": _bucketize(r["lat"] for r in rows),
               "timeline": _timeline(rows)}

    if kind == "osdtrace":
        bytype = Counter(r["op"] for r in rows)
        summary["byType"] = bytype.most_common()
        total = sum(r["lat"] for r in rows) or 1
        stage = {
            "messenger": sum(r["throttle_lat"] + r["recv_lat"]
                             + r["dispatch_lat"] for r in rows),
            "queue": sum(r["queue_lat"] for r in rows),
            "osd": sum(r["osd_lat"] for r in rows),
            "bluestore": sum(r["bluestore_lat"] for r in rows),
        }
        payload["stages"] = [[k, round(100 * v / total)]
                             for k, v in stage.items()]
        kv_commit = sum(r["bluestore_details"].get("kv_commit", 0)
                        for r in rows)
        payload["kvCommit"] = round(100 * kv_commit / total)
        groups = defaultdict(list)
        for row in rows:
            groups[row["osd"]].append(row["lat"])
        payload["groupLabel"] = "OSD"
        payload["groups"], payload["histGroups"] = _group_stats(groups)
        payload["slowest"] = [
            {"lat": r["lat"], "op": r["op"], "osd": r["osd"], "pg": r["pg"],
             "size": _hsize(r["size"])}
            for r in sorted(rows, key=lambda r: -r["lat"])[:50]]
    else:
        summary["reads"] = sum(1 for r in rows if r["wr"] == "R")
        summary["writes"] = sum(1 for r in rows if r["wr"] == "W")
        summary["byType"] = [["read", summary["reads"]],
                             ["write", summary["writes"]]]
        groups = defaultdict(list)
        for row in rows:
            groups[row["pool"]].append(row["lat"])
        payload["groupLabel"] = "Pool"
        payload["groups"], payload["histGroups"] = _group_stats(groups)
        payload["slowest"] = [
            {"lat": r["lat"], "wr": r["wr"], "pool": r["pool"],
             "obj": r["obj"]}
            for r in sorted(rows, key=lambda r: -r["lat"])[:50]]
    return payload


def _write_html(payload, out_path):
    """Inline the payload into the template and write a standalone .html."""
    template = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "report_template.html")
    with open(template, encoding="utf-8") as handle:
        html = handle.read()
    # Compact, and neutralize any "</script>" that could ride in on an object
    # name by escaping "<".
    blob = json.dumps(payload, separators=(",", ":")).replace("<", "\\u003c")
    with open(out_path, "w", encoding="utf-8") as handle:
        handle.write(html.replace("__CEPHTRACE_DATA__", blob))


def main():
    """Read a file arg or stdin, detect the tool, print or write a report."""
    if "-h" in sys.argv or "--help" in sys.argv:
        print(__doc__)
        return 0
    argv = sys.argv[1:]
    html_out = None
    if "--html" in argv:
        idx = argv.index("--html")
        if idx + 1 >= len(argv):
            print("--html requires an output filename", file=sys.stderr)
            return 2
        html_out = argv[idx + 1]
        del argv[idx:idx + 2]
    positional = [a for a in argv if not a.startswith("-")]

    if positional:
        path = positional[0]
        with open(path, encoding="utf-8", errors="replace") as handle:
            lines = handle.readlines()
        is_csv = detect_file_format(path) == "csv"
    else:
        lines = sys.stdin.readlines()
        is_csv = any("," in ln for ln in lines[:5] if ln.strip())

    kind, rows = _load(lines, is_csv)
    if not rows:
        print(f"no {kind} rows recognized", file=sys.stderr)
        return 1

    if html_out:
        _write_html(_build_payload(kind, rows), html_out)
        print(f"wrote {html_out} ({kind}, {len(rows)} ops)")
        return 0

    width = shutil.get_terminal_size((90, 24)).columns
    if kind == "osdtrace":
        report_osdtrace(rows, width)
    else:
        report_radostrace(rows, width)
    return 0


if __name__ == "__main__":
    sys.exit(main())
