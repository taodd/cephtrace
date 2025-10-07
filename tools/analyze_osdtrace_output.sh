#!/usr/bin/env python3
import argparse
import re
import json
import statistics
from enum import Enum

class OpType(Enum):
    OP = "op"
    SUBOP = "subop"


pattern_size = re.compile(r"size (\d+)")
pattern_peers = re.compile(r"peers \[(.*?)\]")
pattern_ops_lat = re.compile(
    r"osd\s+(?P<osd>\d+)\s+"
    r"pg\s+(?P<pg>\S+)\s+"
    r"(?P<op>\S+)\s+"
    r"size\s+(?P<size>\d+)\s+"
    r"client\s+(?P<client>\d+)\s+"
    r"tid\s+(?P<tid>\d+)\s+"
    r"throttle_lat\s+(?P<throttle_lat>\d+)\s+"
    r"recv_lat\s+(?P<recv_lat>\d+)\s+"
    r"dispatch_lat\s+(?P<dispatch_lat>\d+)\s+"
    r"queue_lat\s+(?P<queue_lat>\d+)\s+"
    r"osd_lat\s+(?P<osd_lat>\d+)\s+"
    r"peers\s+(?P<peers>\[.*?\])\s+"
    r"bluestore_lat\s+(?P<bluestore_lat>\d+)\s+\((?P<bluestore_details>.*)\)\s+"
    r"op_lat\s+(?P<op_lat>\d+)"
)
pattern_subop_lat = re.compile(
    r"osd\s+(?P<osd>\d+)\s+"
    r"pg\s+(?P<pg>\S+)\s+"
    r"(?P<op>\S+)\s+"
    r"size\s+(?P<size>\d+)\s+"
    r"client\s+(?P<client>\d+)\s+"
    r"tid\s+(?P<tid>\d+)\s+"
    r"throttle_lat\s+(?P<throttle_lat>\d+)\s+"
    r"recv_lat\s+(?P<recv_lat>\d+)\s+"
    r"dispatch_lat\s+(?P<dispatch_lat>\d+)\s+"
    r"queue_lat\s+(?P<queue_lat>\d+)\s+"
    r"osd_lat\s+(?P<osd_lat>\d+)\s+"
    r"bluestore_lat\s+(?P<bluestore_lat>\d+)\s+\((?P<bluestore_details>.*)\)\s+"
    r"subop_lat\s+(?P<subop_lat>\d+)"
)


def parse_line(line: str = "") -> list:
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


def parse_line_ops_lat(line: str = "") -> list:
    m = pattern_ops_lat.search(line)
    if not m:
        return []

    data = m.groupdict()

    peers = re.findall(r"\((\d+),\s*(\d+)\)", data["peers"])
    data["peers"] = [(int(a), int(b)) for a, b in peers]

    details = re.findall(r"(\w+)\s+(\d+)", data["bluestore_details"])
    data["bluestore_details"] = {k: int(v) for k, v in details}

    for key in [
        "osd", "size", "client", "tid", "throttle_lat", "recv_lat",
        "dispatch_lat", "queue_lat", "osd_lat", "bluestore_lat", "op_lat"
    ]:
        data[key] = int(data[key])

    return [data]


def parse_line_subop_lat(line: str = "") -> list:
    m = pattern_subop_lat.search(line)
    if not m:
        return []

    data = m.groupdict()

    details = re.findall(r"(\w+)\s+(\d+)", data["bluestore_details"])
    data["bluestore_details"] = {k: int(v) for k, v in details}

    for key in [
        "osd", "size", "client", "tid", "throttle_lat", "recv_lat",
        "dispatch_lat", "queue_lat", "osd_lat", "bluestore_lat", "subop_lat"
    ]:
        data[key] = int(data[key])

    return [data]


def parse_file(file: str, op_type: OpType) -> list:
    all_entries = []
    handler = parse_line_ops_lat if op_type == OpType.OP else parse_line_subop_lat
    with open(file, 'r') as f:
        for line in f:
            entries = handler(line)
            all_entries.extend(entries)
    return all_entries



def analyze(op_type: OpType, data: list = [], slow_threshold: int = 1000, show_in_ms: bool = False, generic_thresholds: str = "100,1000", breakdown_bluestore: bool = False) -> dict:
    results = {}
    final_results = {}
    unit = "ms" if show_in_ms else "us"
    rounding_precision = 2
    mode = op_type.value
    generic_thresholds = generic_thresholds.split(",")

    for trace in data:
        osd = trace["osd"]
        if osd not in results:
            results[osd] = {
                f"{mode} data": [],
                f"slow {mode} data": [],
                f"slow {mode} data distribution": {},
            }
            for thresh in generic_thresholds:
                results[osd][f"generic threshold {thresh}"] = []
            final_results[f"osd.{osd}"] = {}

        final_lat = trace[f"{mode}_lat"]
        for thresh in generic_thresholds:
            if final_lat > int(thresh):
                results[osd][f"generic threshold {thresh} count"] = results[osd].get(f"generic threshold {thresh} count", 0) + 1

        if final_lat > slow_threshold:
            highest_metric_value = -1
            highest_metric = None
            for metric, value in trace.items():
                if metric.endswith("_lat") and metric != f"{mode}_lat":
                    if value > highest_metric_value:
                        highest_metric_value = value
                        highest_metric = metric

            results[osd][f"slow {mode} data"].append(final_lat)
            results[osd][f"slow {mode} data distribution"][highest_metric] = results[osd][f"slow {mode} data distribution"].get(highest_metric, 0) + 1

        if breakdown_bluestore:
            bluestore_metrics = trace.get("bluestore_details", {})
            if f"{mode} bluestore data" not in results[osd]:
                results[osd][f"{mode} bluestore data"] = {key: [] for key in bluestore_metrics.keys()}

            for metric, value in bluestore_metrics.items():
                results[osd][f"{mode} bluestore data"][metric].append(value)

        results[osd][f"{mode} data"].append(final_lat)


    for osdid, info in results.items():
        osd = f"osd.{osdid}"
        avg = statistics.mean(info[f"{mode} data"])
        stdev = statistics.stdev(info[f"{mode} data"])
        median = statistics.median(info[f"{mode} data"])
        ops_subops_count= len(info[f"{mode} data"])
        slow_ops_subops_count = len(info[f"slow {mode} data"])
        max_lat = max(info[f"{mode} data"])
        min_lat = min(info[f"{mode} data"])

        if show_in_ms:
            avg = avg / 1000
            stdev = stdev / 1000
            median = median / 1000
            max_lat = max_lat / 1000
            min_lat = min_lat / 1000
            rounding_precision = 5

        final_results[osd]["Average Latency"] = f"{round(avg, rounding_precision)} {unit}"
        final_results[osd]["Standard Deviation of Latencies"] = f"{round(stdev, rounding_precision)} {unit}"
        final_results[osd]["Median Latency"] = f"{median} {unit}"
        final_results[osd]["Max Latency"] = f"{max_lat} {unit}"
        final_results[osd]["Min Latency"] = f"{min_lat} {unit}"
        final_results[osd][f"Total number of {mode}"] = ops_subops_count
        final_results[osd][f"Percantage of slow {mode}"] = f"{round((slow_ops_subops_count / ops_subops_count) * 100, 2)} %"
        final_results[osd][f"Total number of slow {mode}"] = slow_ops_subops_count
        final_results[osd][f"Maximum contributing factor of slow {mode}"] = info[f"slow {mode} data distribution"]

        for thresh in generic_thresholds:
            final_results[osd][f"Latency > {thresh} {unit}"] = info[f"generic threshold {thresh} count"]

        if breakdown_bluestore:
            final_results[osd]["Bluestore Distribution"] = {}
            for metric, values in info[f"{mode} bluestore data"].items():
                bavg = statistics.mean(values)
                if show_in_ms:
                    bavg = bavg / 1000
                final_results[osd]["Bluestore Distribution"][f"Average {metric}"] = f"{round(bavg, rounding_precision)} {unit}"
                final_results[osd]["Bluestore Distribution"][f"Max {metric}"] = f"{max(values)}"

    return final_results


def main(args) -> None:
    if args.ops_latency:
        print(f"Analyzing latencies of main operations with a slow threshold of {args.slow_ops_threshold} μs...")
        parsed_data = parse_file(args.osdtrace_file, OpType.OP)
        results = analyze(OpType.OP, parsed_data, args.slow_ops_threshold, args.show_in_ms, args.ops_thresholds, args.breakdown_bluestore)
        print(json.dumps(results, indent=4))

    if args.subops_latency:
        print(f"Analyzing latencies of sub operations with a slow threshold of {args.slow_subops_threshold} μs...")
        parsed_data = parse_file(args.osdtrace_file, OpType.SUBOP)
        results = analyze(OpType.SUBOP, parsed_data, args.slow_subops_threshold, args.show_in_ms, args.subops_thresholds, args.breakdown_bluestore)
        print(json.dumps(results, indent=4))

    # all_entries = parse_file(args.osdtrace_file, parse_line)

    # # sort by latency
    # all_entries.sort(key=lambda x: x[2])

    # for size, pid, lat in all_entries:
    #     print(f"{size} {pid} {lat}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("osdtrace_file", help="Path to osdtrace output file")
    parser.add_argument("-o", "--ops-latency", help="Analyze ops latency in osdtrace", action="store_true", default=True)
    parser.add_argument("-s", "--subops-latency", help="Analyze subops latency in osdtrace", action="store_true", default=True)
    parser.add_argument("-m", "--show-in-ms", help="Use milliseconds for analysis output (default is microseconds)", action="store_true")
    parser.add_argument("-b", "--breakdown-bluestore", help="Show analysis of bluestore operations", action="store_true")
    parser.add_argument("--ops-thresholds", help="Comma separated values of generic threshold values in microseconds", default="100,1000", type=str)
    parser.add_argument("--subops-thresholds", help="Comma separated values of generic threshold values in microseconds", default="100,1000", type=str)
    parser.add_argument("--slow-ops-threshold", help="Number of microseconds above which the operation is considered slow", default=1000, type=int)
    parser.add_argument("--slow-subops-threshold", help="Number of microseconds above which the sub-operation is considered slow", default=1000, type=int)
    args = parser.parse_args()

    main(args)

