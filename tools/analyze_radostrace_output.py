#!/usr/bin/env python3
"""
Analyzes rados trace output to identify problematic OSDs involved in
high-latency operations.
"""
import sys
import re
from collections import defaultdict


def parse_args():
    """
    Parses CLI arguments: log file, osd tree file, and latency threshold.
    """
    if len(sys.argv) < 3:
        print("Usage: ./analyze_radostrace_output.sh <log_file> "
              "<osd_tree_file> [latency_threshold_in_microseconds]")
        print("  latency_threshold defaults to 100000 microseconds (100ms) "
              "if not specified")
        sys.exit(1)

    log_file = sys.argv[1]
    osd_tree_file = sys.argv[2]

    # Default threshold is 100ms = 100000 microseconds
    latency_threshold = 100000

    if len(sys.argv) >= 4:
        try:
            latency_threshold = int(sys.argv[3])
        except ValueError:
            print("Error: latency_threshold must be an integer")
            sys.exit(1)

    return log_file, osd_tree_file, latency_threshold


def parse_log_file(log_file, threshold):
    """
    Parses the log file, filtering entries above the latency threshold.
    Returns counts of high-latency occurrences per OSD and a list of OSD lists
    (one for each high-latency entry).
    """
    osd_counts = defaultdict(int)
    osd_entries = []  # Store each entry's OSD list for subsequent passes

    with open(log_file, 'r', encoding='utf-8') as file_handle:
        for line in file_handle:
            # Skip empty lines
            if not line.strip():
                continue

            parts = line.split()

            # Check if line has enough columns
            if len(parts) < 9:
                continue

            # Parse latency (9th column, 0-based index 8)
            try:
                latency = int(parts[8])
            except (ValueError, IndexError):
                continue

            # Check latency threshold
            if latency < threshold:
                continue

            # Parse OSD list (6th column, index 5)
            osd_list_str = parts[5]
            osd_list = re.findall(r'\d+', osd_list_str)
            osd_entries.append(osd_list)

            # Count each OSD
            for osd in osd_list:
                osd_counts[osd] += 1

    return osd_counts, osd_entries


def parse_osd_tree(osd_tree_file):
    """
    Parses the OSD tree file (output of `ceph osd tree`) to map OSD IDs to
    host names.
    """
    osd_to_host = {}
    current_host = None

    with open(osd_tree_file, 'r', encoding='utf-8') as file_handle:
        for line in file_handle:
            # Skip empty lines and summary lines
            if not line.strip() or line.startswith("ID") or \
               line.startswith("MIN/MAX") or line.startswith("TOTAL"):
                continue

            # Check for host lines (start with - and have "host" in them)
            if line.startswith('-') and 'host' in line:
                current_host = line.split()[-1]

            # Check for OSD lines (they have osd.X in them)
            if 'osd.' in line:
                parts = line.split()
                for part in parts:
                    if part.startswith('osd.'):
                        osd_num = part.split('.')[1]
                        osd_to_host[osd_num] = current_host
                        break

    return osd_to_host


def count_osds_in_entries(entries):
    """Count occurrences of each OSD in the given entries."""
    counts = defaultdict(int)
    for entry in entries:
        for osd in entry:
            counts[osd] += 1
    return counts


def print_summary(problematic_osds, total_operations):
    """Print final summary of all problematic OSDs."""
    if not problematic_osds:
        print("\nNo problematic OSDs identified.")
        return

    print("\n" + "=" * 70)
    print("=== SUMMARY: Problematic OSDs Identified ===")
    print("=" * 70)
    header_format = "{:<6} {:<10} {:<8} {:<20} {:<10}"
    print(header_format.format("Rank", "OSD", "Count", "Host", "Iteration"))
    print("-" * 70)

    for rank, (osd, count, host, iteration) in enumerate(problematic_osds,
                                                         start=1):
        print(header_format.format(
            rank,
            f"osd.{osd}",
            count,
            host,
            iteration
        ))

    print("-" * 70)
    print(f"Total problematic OSDs identified: {len(problematic_osds)}")
    print(f"Total high-latency operations analyzed: {total_operations}")
    print("=" * 70)


def print_results(osd_counts, osd_entries, osd_to_host):
    """
    Performs the iterative analysis and prints the final results.
    """
    if not osd_counts:
        print("No matching entries found with the given criteria.")
        return

    total_operations = len(osd_entries)
    # List of tuples: (osd, count, host, iteration)
    problematic_osds = []
    remaining_entries = osd_entries
    iteration = 1

    print("\n" + "=" * 70)
    print("Starting iterative analysis to identify problematic OSDs...")
    print("=" * 70)

    while True:
        # Count OSDs in remaining entries
        current_counts = count_osds_in_entries(remaining_entries)

        if not current_counts:
            print(f"\n[Iteration {iteration}] No more high-latency "
                  "operations found.")
            break

        # Find top OSD
        top_osd = max(current_counts.items(), key=lambda x: x[1])[0]
        count = current_counts[top_osd]
        host = osd_to_host.get(top_osd, "Unknown")

        # Record it
        problematic_osds.append((top_osd, count, host, iteration))
        print(f"[Iteration {iteration}] Top OSD: osd.{top_osd} ({count} "
              f"occurrences on {host})")

        # Exclude entries containing this OSD
        # Filter out all entries that contain the top OSD
        remaining_entries = [entry for entry in remaining_entries
                             if top_osd not in entry]
        iteration += 1

    # Print final summary
    print_summary(problematic_osds, total_operations)


def main():
    """Main function to orchestrate the analysis."""
    log_file, osd_tree_file, latency_threshold = parse_args()

    print(f"Analyzing log file: {log_file}")
    print(f"OSD tree file: {osd_tree_file}")
    print(f"Latency threshold: {latency_threshold} microseconds "
          f"({latency_threshold/1000.0:.1f} ms)")

    # Parse the log file to get OSD counts and all entries
    osd_counts, osd_entries = parse_log_file(log_file, latency_threshold)

    # Parse the OSD tree file to get OSD to host mapping
    osd_to_host = parse_osd_tree(osd_tree_file)

    # Print the results
    print_results(osd_counts, osd_entries, osd_to_host)


if __name__ == "__main__":
    main()
