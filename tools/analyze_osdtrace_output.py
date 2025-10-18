#!/usr/bin/env python3
import argparse
import re
import json
import statistics
from enum import Enum
from math import ceil
from textwrap import dedent, indent

OP_TYPES= ["op_r", "op_w", "subop_r", "subop_w"]
BLUESTORE_OP_TYPES = ["prepare", "aio_wait", "aio_size", "seq_wait", "kv_commit"]
EPILOGUE_HELP = dedent('''
To run the tool, you need to have a osdtrace file,

    ./analyze_osdtrace_output.py osdtrace.out

The flags of show_ms, osd and field apply to all methods.

    Prints statistical analysis but for kv_commit latencies
        ./analyze_osdtrace_output.py osdtrace.out -f kv_commit

    Prints statistical analysis but for kv_commit latencies and osd 22
        ./analyze_osdtrace_output.py osdtrace.out -f kv_commit -o 22

    Prints sorted lines for kv_commit latencies
        ./analyze_osdtrace_output.py osdtrace.out -s -f kv_commit
''')

class CustomFormatter(argparse.ArgumentDefaultsHelpFormatter, argparse.RawDescriptionHelpFormatter):
    pass

pattern_size = re.compile(r"size (\d+)")
pattern_peers = re.compile(r"peers \[(.*?)\]")
pattern_lat = re.compile(
    r"osd\s+(?P<osd>\d+)\s+"
    r"pg\s+(?P<pg>\S+)\s+"
    r"(?P<op>(?:sub)?op_[wr])\s+"
    r"size\s+(?P<size>\d+)\s+"
    r"client\s+(?P<client>\d+)\s+"
    r"tid\s+(?P<tid>\d+)\s+"
    r"throttle_lat\s+(?P<throttle_lat>\d+)\s+"
    r"recv_lat\s+(?P<recv_lat>\d+)\s+"
    r"dispatch_lat\s+(?P<dispatch_lat>\d+)\s+"
    r"queue_lat\s+(?P<queue_lat>\d+)\s+"
    r"osd_lat\s+(?P<osd_lat>\d+)\s+"
    r"(?:peers\s+(?P<peers>\[.*?\])\s+)?"   # peers are only in write ops
    r"bluestore_lat\s+(?P<bluestore_lat>\d+)"
    r"(?:\s*\((?P<bluestore_details>.*?)\))?"  # bluestore latencies are only in write
    r"(?:\s+)?"
    r"(?P<lat_type>(?:sub)?op_lat)\s+(?P<lat>\d+)"
)


def parse_line_sp(line: str = "") -> list:
    size_match = pattern_size.search(line)
    peers_match = pattern_peers.search(line)
    if not size_match or not peers_match:
        return []

    size = int(size_match.group(1))
    peers_raw = peers_match.group(1)
    # extract tuples like (4, 631)
    peers = re.findall(r"\((\d+),\s*(\d+)\)", peers_raw)
    entries = [(size, int(pid), int(lat)) for pid, lat in peers]
    return entries


def parse_line(line: str = "") -> list:
    m = pattern_lat.search(line)
    if not m:
        return []

    data = m.groupdict()

    # Parse peers if present
    if data.get("peers"):
        peers = re.findall(r"\((\d+),\s*(\d+)\)", data["peers"])
        data["peers"] = [(int(a), int(b)) for a, b in peers]
    else:
        data["peers"] = []

    # Parse bluestore details into dict
    if data.get("bluestore_details"):
        details = re.findall(r"(\w+)\s+(\d+)", data["bluestore_details"])
        data["bluestore_details"] = {k: int(v) for k, v in details}
    else:
        data["bluestore_details"] = {}

    # Convert all relevant numeric fields
    for key in [
        "osd", "size", "client", "tid", "throttle_lat",
        "recv_lat", "dispatch_lat", "queue_lat",
        "osd_lat", "bluestore_lat", "lat"
    ]:
        data[key] = int(data[key])

    return [data]


def parse_file(file: str) -> list:
    all_entries = []
    with open(file, 'r') as f:
        for line in f:
            entries = parse_line(line)
            all_entries.extend(entries)
    return all_entries


def sort(
    data: list = [],
    show_in_ms: bool = False,
    field: str = "lat",
    single_osd: int = -1,
) -> None:
    """Print a (descending) sorted view of osd(s) operation latencies.
    
    data: List of parsed osdtrace lines
    show_in_ms: Show final timestamps in milliseconds, instead of microseconds
    field: Specify a single latency field to analyze
    single_osd: Specify a single osd to filter
    """
    def _format_ts(k: str, v: int):
        if k.endswith("lat") or k in BLUESTORE_OP_TYPES:
            return round(v / 1000, 2) if show_in_ms else v
        else:
            return v

    if single_osd >= 0:
        filtered_data = filter(lambda t: t["osd"] == single_osd, data)
    else:
        filtered_data = data

    bd = "bluestore_details"
    if field in BLUESTORE_OP_TYPES:
        sorted_data = sorted(filtered_data, key=lambda t: t.get(bd, {}).get(field, -1))
    else:
        sorted_data = sorted(filtered_data, key=lambda t: t[field])

    for trace in sorted_data:
        if bd in trace:
            trace[bd] = "(" + " ".join(f"{k} {_format_ts(k, v)}" for k, v in trace[bd].items()) + ")"
        print(" ".join(f"{k} {_format_ts(k, v)}" if k != bd else v for k, v in trace.items()))


def format_percentile_value_display(width: int, value: float) -> str:
    formatted_value = f"{value:.2f}"
    leading_spaces = " " * (width - len(formatted_value))
    return f"{leading_spaces}{formatted_value}"


def calc_percentiles(unsorted_data: list[int], thresholds: list[float]) -> list[float]:
    """Calculated using the nearest-rank method.

    Ref: https://en.wikipedia.org/wiki/Percentile#The_nearest-rank_method

    Alternative is to use numpy.percentiles()
    """

    percentiles = []
    data = sorted(unsorted_data)
    N = len(data)

    for P in thresholds:
        n = ceil((P / 100) * N)
        percentiles.append(data[n-1])

    return percentiles

def analyze(
    data: list = [],
    show_in_ms: bool = False,
    field: str = "lat",
    single_osd: int = -1,
) -> None:
    """Print a statiscal analysis of osd(s) operation latencies.
    
    data: List of parsed osdtrace lines
    show_in_ms: Show final timestamps in milliseconds, instead of microseconds
    field: Specify a single latency field to analyze
    single_osd: Specify a single osd to analyze
    """
    results = {}
    unit = "msec" if show_in_ms else "μsec"

    # aggregate data over each operation type
    # group by osd so we can print all data for a given osd at once
    for trace in data:
        osd = trace["osd"]
        if single_osd >= 0 and single_osd != osd:
            # Only collect data for a single osd if a single osd was specified
            continue

        if osd not in results:
            results[osd] = {
                f"{op_type}_data": [] for op_type in OP_TYPES
            }

        if field in BLUESTORE_OP_TYPES:
            if "bluestore_details" in trace:
                if field in trace["bluestore_details"]:
                    results[osd][f"{trace['op']}_data"].append(trace["bluestore_details"][field])
        else:
            results[osd][f"{trace['op']}_data"].append(trace[field])

    for osdid, info in results.items():
        print(f"osd.{osdid}:")
        for op_type in OP_TYPES:
            lat_data = info[f"{op_type}_data"]
            if not lat_data:
                continue

            avg = statistics.mean(lat_data)
            stdev = statistics.stdev(lat_data)
            max_lat = max(lat_data)
            min_lat = min(lat_data)

            if show_in_ms:
                avg = avg / 1000
                stdev = stdev / 1000
                max_lat = max_lat / 1000
                min_lat = min_lat / 1000
                lat_data = [x / 1000 for x in lat_data] 

            percentile_thresholds = [1, 5] + [i*10 for i in range(1,10)] + [95, 99, 99.5, 99.9]
            percentiles = calc_percentiles(lat_data, percentile_thresholds)
            print(f"  {op_type} {field} ({unit}): min={min_lat}, max={max_lat}, avg={avg:.2f}, stdev={stdev:.2f}, samples={len(lat_data)}")
            print(f"  {field} percentiles ({unit}):")
            num_percentile_per_line = 3
            num_percentile_lines = len(percentile_thresholds) // num_percentile_per_line
            percentile_display_width = len(str(f"{percentiles[-1]:.2f}"))
            for pt in range(num_percentile_lines + 1):
                pline = ""
                for sub_pt in range(num_percentile_per_line):
                    idx = (pt * num_percentile_per_line) + sub_pt
                    if idx < len(percentile_thresholds):
                        value = format_percentile_value_display(percentile_display_width, percentiles[idx])
                        percentile_threshold = f"{percentile_thresholds[idx]:.2f}"
                        leading_space = " " if len(percentile_threshold) == 4 else ""
                        pline += f" {leading_space}{percentile_threshold}th=[{value}],"
                if pline:
                    if pt == num_percentile_lines - 1:
                        pline = pline[:-1]
                    print(f"  | {pline}")

            print()


def main(args) -> None:
    # validate the field parameter
    if (not args.field.endswith("lat")) and (args.field not in BLUESTORE_OP_TYPES):
        print(f"{args.field} does not seem like a latency field, exiting...")
        exit(1)

    parsed_data = parse_file(args.osdtrace_file)

    if args.sort:
        sort(parsed_data, args.show_in_ms, args.field, args.osd)
    else:
        analyze(parsed_data, args.show_in_ms, args.field, args.osd)



if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        formatter_class=CustomFormatter,
        epilog=EPILOGUE_HELP,
    )
    parser.add_argument("osdtrace_file", help="Path to osdtrace output file")
    parser.add_argument("-o", "--osd", help="ID of a single OSD to analyze", default=-1, type=int)
    parser.add_argument("-m", "--show-in-ms", help="Use milliseconds for analysis output (default is microseconds)", action="store_true")
    parser.add_argument("-s", "--sort", help="Sort osdtrace log lines by latency value as specified by '--field'", action="store_true")
    parser.add_argument("-f", "--field", help="Latency field to analyze of each operation type, by default only the final latencies are analyzed", default="lat")
    parser.add_argument("-j", "--json", help="Print output in json format", action="store_true")
    args = parser.parse_args()

    main(args)
