#!/usr/bin/env python3
"""
Analyzes osdtrace output to identify problematic OSDs involved in
high-latency operations and print fio-style output.
"""

import argparse
import re
import statistics
import sys
from math import ceil
from textwrap import dedent

OP_TYPES = ["op_r", "op_w", "subop_r", "subop_w"]
BLUESTORE_OP_TYPES = {"prepare", "aio_wait", "aio_size", "seq_wait",
                      "kv_commit"}
NUM_PERCENTILE_PER_LINE = 3  # number of percentile entries per line
DEFAULT_LATENCY_FIELD = "lat"

EPILOGUE_HELP = dedent(
    """
    To run the tool, you need to have an osdtrace file,
    ./analyze_osdtrace_output.py osdtrace.out

    The flags of show_ms, osd and field apply to all methods.

    Prints statistical analysis but for kv_commit latencies
    ./analyze_osdtrace_output.py osdtrace.out -f kv_commit

    Prints statistical analysis but for recv_lat latencies and osd 22
    ./analyze_osdtrace_output.py osdtrace.out -f recv_lat -o 22

    Prints sorted lines for kv_commit latencies
    ./analyze_osdtrace_output.py osdtrace.out -f kv_commit -s
    """
)


class CustomFormatter(argparse.ArgumentDefaultsHelpFormatter,
                      argparse.RawDescriptionHelpFormatter):
    """ Argument formatter class """


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
    # peers are only in write ops
    r"(?:peers\s+(?P<peers>\[.*?\])\s+)?"
    r"bluestore_lat\s+(?P<bluestore_lat>\d+)"
    # bluestore latencies are only in write
    r"(?:\s*\((?P<bluestore_details>.*?)\))?"
    r"(?:\s+)?"
    r"(?P<lat_type>(?:sub)?op_lat)\s+(?P<lat>\d+)"
)


def parse_line(line: str = "") -> list:
    """ Parse a line of output from osdtrace and return results in a list """
    match = pattern_lat.search(line)
    if not match:
        return []

    data = match.groupdict()

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


def parse_file(filepath: str) -> list:
    """ Parse the osdtrace log file """
    all_entries = []
    with open(filepath, "r", encoding="utf-8") as file_obj:
        for line in file_obj:
            entries = parse_line(line)
            all_entries.extend(entries)
    return all_entries


def sort(
    data: list,
    show_in_ms: bool = False,
    field: str = DEFAULT_LATENCY_FIELD,
) -> None:
    """Print a (descending) sorted view of osd(s) operation latencies.

    Args:
        data: List of parsed osdtrace lines.
        show_in_ms: Show final timestamps in milliseconds, instead of μsecs.
        field: Specify a single latency field to analyze.
    """
    def _format_ts(key: str, value: int) -> float | int:
        if key.endswith("lat") or key in BLUESTORE_OP_TYPES:
            return round(value / 1000, 2) if show_in_ms else value
        return value

    bd = "bluestore_details"

    if field in BLUESTORE_OP_TYPES:
        sorted_data = sorted(
            data, key=lambda t: t.get(bd, {}).get(field, -1),
            reverse=True
        )
    else:
        sorted_data = sorted(data, key=lambda t: t[field],
                             reverse=True)

    for trace in sorted_data:
        if bd in trace:
            bd_details = " ".join(
                f"{k} {_format_ts(k, v)}" for k, v in trace[bd].items()
            )
            trace[bd] = f"({bd_details})"
        print(
            " ".join(
                f"{k} {_format_ts(k, v)}" if k != bd else v
                for k, v in trace.items()
            )
        )


def group_by_osd_and_op(
    data: list,
    field: str = DEFAULT_LATENCY_FIELD
) -> dict:
    """Group parsed osdtrace lines by osd and operation type.

    Aggregate data over each operation type
    Group by osd so we can print all data for a given osd at once

    Args:
        data: List of parsed osdtrace lines.
    """
    results = {}
    for trace in data:
        osd = trace["osd"]
        if osd not in results:
            results[osd] = {f"{op_type}_data": [] for op_type in OP_TYPES}
        if field in BLUESTORE_OP_TYPES:
            if "bluestore_details" in trace:
                if field in trace["bluestore_details"]:
                    results[osd][f"{trace['op']}_data"].append(
                        trace["bluestore_details"][field]
                    )
        else:
            results[osd][f"{trace['op']}_data"].append(trace[field])

    return results


# pylint: disable=too-many-locals
def infer(data: list) -> None:
    """Infer % contributions from latency fields.

    Args:
        data: List of parsed osdtrace lines.
    """
    final_latency_field = "lat"
    results = {}

    for trace in data:
        # group by osd
        if trace["osd"] not in results:
            results[trace["osd"]] = {}
        # group each osd by op type
        if trace["op"] not in results[trace["osd"]]:
            results[trace["osd"]][trace["op"]] = {}
        # group each op type by field
        for field, latency in trace.items():
            if field != final_latency_field:
                if field.endswith("lat") or field in BLUESTORE_OP_TYPES:
                    contribution = (latency / trace[final_latency_field]) * 100
                    if contribution >= 100.0:
                        contribution = 99.99  # or ignore this value?
                    if field not in results[trace["osd"]][trace["op"]]:
                        results[trace["osd"]][trace["op"]][field] = []
                    results[trace["osd"]][trace["op"]][field].append(
                        contribution
                    )

    for osd_id, ops in results.items():
        print(f"osd.{osd_id}:")
        for op_type, fields in ops.items():
            print(f"  {op_type}:")

            field_to_contribution = {}
            for field, contributions in fields.items():
                field_to_contribution[field] = statistics.mean(contributions)

            sorted_fields = sorted(
                field_to_contribution.items(),
                key=lambda item: item[1],
                reverse=True
            )

            max_width = len(f"{sorted_fields[0][1]:.2f}")
            for field, avg_contribution in sorted_fields:
                avg_cont_str = f"{avg_contribution:.2f}"
                leading_spaces = " " * (max_width - len(avg_cont_str))
                print(f"    {leading_spaces}{avg_cont_str}% from {field}")

        print()


def format_percentile_value_display(width: int, value: float) -> str:
    """Format percentile float value display with leading spaces."""
    formatted_val = f"{value:.2f}"
    leading_spaces = " " * (width - len(formatted_val))
    return f"{leading_spaces}{formatted_val}"


def calc_percentiles(
    unsorted_data: list[int],
    thresholds: list[float],
) -> list[float]:
    """Calculate percentiles using the nearest-rank method.

    Ref: https://en.wikipedia.org/wiki/Percentile#The_nearest-rank_method

    Alternative is to use numpy.percentiles()
    """
    percentiles = []
    data = sorted(unsorted_data)
    n = len(data)
    for p in thresholds:
        rank = ceil((p / 100) * n)
        percentiles.append(data[rank - 1])
    return percentiles


def print_percentiles(lat_data: list) -> None:
    """Print FIO style latency percentiles."""
    percentile_thresholds = (
        [1, 5] + [i*10 for i in range(1, 10)] + [95, 99, 99.5, 99.9]
    )
    percentiles = calc_percentiles(lat_data, percentile_thresholds)

    # number of lines of percentiles to print
    num_lines = len(percentile_thresholds) // NUM_PERCENTILE_PER_LINE

    # widths of percentile thresholds are determined by the longest threshold
    p_thresh_display_min_width = len(str(f"{percentile_thresholds[0]:.2f}"))
    p_thresh_display_max_width = len(str(f"{percentile_thresholds[-1]:.2f}"))
    leading_space_offset = (
        p_thresh_display_max_width - p_thresh_display_min_width
    )

    # widths of percentile values are determined by the longest value
    max_percentile_display_width = len(str(f"{percentiles[-1]:.2f}"))

    for pt in range(num_lines + 1):
        pline = ""
        for sub_pt in range(NUM_PERCENTILE_PER_LINE):
            idx = (pt * NUM_PERCENTILE_PER_LINE) + sub_pt
            if idx < len(percentile_thresholds):
                value = format_percentile_value_display(
                    max_percentile_display_width,
                    percentiles[idx],
                )
                threshold = f"{percentile_thresholds[idx]:.2f}"
                leading_space = ""
                if len(threshold) == p_thresh_display_min_width:
                    leading_space = " " * leading_space_offset
                pline += f" {leading_space}{threshold}th=[{value}],"
        if pline:
            if pt == num_lines - 1:
                pline = pline[:-1]
            print(f"  | {pline}")


# pylint: disable=too-many-locals, too-many-branches
def analyze(
    data: list,
    show_in_ms: bool = False,
    field: str = DEFAULT_LATENCY_FIELD,
) -> None:
    """Print a statistical analysis of osd(s) operation latencies.

    Args:
        data: List of parsed osdtrace lines.
        show_in_ms: Show final timestamps in milliseconds, instead of μsecs.
        field: Specify a single latency field to analyze.
    """
    grouped_data = group_by_osd_and_op(data, field)
    unit = "msec" if show_in_ms else "μsec"

    for osd_id, info in grouped_data.items():
        print(f"osd.{osd_id}:")
        for op_type in OP_TYPES:
            lat_data = info[f"{op_type}_data"]
            if not lat_data:
                continue

            avg = statistics.mean(lat_data)
            stdev = statistics.stdev(lat_data) if len(lat_data) > 1 else 0.0
            max_lat = max(lat_data)
            min_lat = min(lat_data)

            if show_in_ms:
                avg = avg / 1000
                stdev = stdev / 1000
                max_lat = max_lat / 1000
                min_lat = min_lat / 1000
                lat_data = [x / 1000 for x in lat_data]

            print(f"  {op_type} {field} ({unit}): min={min_lat}, "
                  f"max={max_lat}, avg={avg:.2f}, stdev={stdev:.2f}, "
                  f"samples={len(lat_data)}")

            print(f"  {field} percentiles ({unit}):")
            print_percentiles(lat_data)

            print()


def main(margs) -> None:
    """ Parse and analyse the osdtrace log """

    # validate the field parameter
    if (not margs.field.endswith("lat")
            and margs.field not in BLUESTORE_OP_TYPES):
        print(f"{margs.field} does not seem like a latency field, exiting...")
        sys.exit(1)

    parsed_data = parse_file(margs.osdtrace_file)
    if margs.osd >= 0:
        filtered_data = list(
            filter(lambda t: t["osd"] == margs.osd, parsed_data)
        )
    else:
        filtered_data = parsed_data

    if margs.sort:
        sort(filtered_data, margs.show_in_ms, margs.field)
    elif margs.infer:
        infer(filtered_data)
    else:
        analyze(filtered_data, margs.show_in_ms, margs.field)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        formatter_class=CustomFormatter,
        epilog=EPILOGUE_HELP,
    )
    parser.add_argument("osdtrace_file", help="Path to osdtrace output file")
    parser.add_argument("-o", "--osd", help="ID of a single OSD to analyze",
                        default=-1, type=int)
    parser.add_argument(
        "-m",
        "--show-in-ms",
        help="Use milliseconds for analysis output (default is microseconds)",
        action="store_true",
    )
    parser.add_argument(
        "-s",
        "--sort",
        help="Sort osdtrace log lines by latency value as specified by '--field'", # noqa
        action="store_true",
    )
    parser.add_argument(
        "-f",
        "--field",
        help=(
            "Latency field to analyze of each operation type, by default only "
            "the final latencies are analyzed"
        ),
        default=DEFAULT_LATENCY_FIELD,
    )
    parser.add_argument(
        "-i",
        "--infer",
        help="Infer individdual percentage contributions from all latency fields", # noqa
        action="store_true",
    )
    args = parser.parse_args()
    main(args)
