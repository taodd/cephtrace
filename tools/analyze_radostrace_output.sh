#!/usr/bin/env python3
import sys
import re
from collections import defaultdict

def parse_args():
    if len(sys.argv) != 5:
        print("Usage: ./analyze_osd_latency.py <log_file> <osd_tree_file> <pid> <latency_threshold in microsecond>")
        sys.exit(1)
    
    log_file = sys.argv[1]
    osd_tree_file = sys.argv[2]
    pid = sys.argv[3]
    
    try:
        latency_threshold = int(sys.argv[4])
    except ValueError:
        print("Error: latency_threshold must be an integer")
        sys.exit(1)
    
    return log_file, osd_tree_file, pid, latency_threshold

def parse_log_file(log_file, pid, threshold):
    osd_counts = defaultdict(int)
    osd_entries = []  # Store each entry's OSD list for subsequent passes
    
    with open(log_file, 'r') as f:
        for line in f:
            # Skip empty lines
            if not line.strip():
                continue
                
            parts = line.split()
            
            # Check if line has enough columns
            if len(parts) < 9:
                continue
                
            # Check PID match
            if parts[0] != pid:
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
    osd_to_host = {}
    current_host = None
    
    with open(osd_tree_file, 'r') as f:
        for line in f:
            # Skip empty lines and summary lines
            if not line.strip() or line.startswith("ID") or line.startswith("MIN/MAX") or line.startswith("TOTAL"):
                continue
                
            # Check for host lines (they start with - and have "host" in them)
            if line.startswith('-') and 'host' in line:
                current_host = line.split()[-1]
                
            # Check for OSD lines (they have osd.X in them)
            if 'osd.' in line:
                parts = line.split()
                for part in parts:
                    if part.startswith('osd.'):
                        osd_num = part.split('.')[1]
                        osd_to_host[osd_num] = current_host
                        
    return osd_to_host

def print_results(osd_counts, osd_entries, osd_to_host):
    if not osd_counts:
        print("No matching entries found with the given criteria.")
        return
        
    # First pass - all OSDs
    print("\n[Primary Analysis] All OSDs:")
    print("{:<8} {:<8} {:<20}".format("OSD", "Count", "Host"))
    print("-" * 40)
    
    # Sort OSDs by count in descending order
    sorted_osds = sorted(osd_counts.items(), key=lambda x: x[1], reverse=True)
    
    for osd, count in sorted_osds:
        host = osd_to_host.get(osd, "Unknown")
        print("{:<8} {:<8} {:<20}".format(f"osd.{osd}", count, host))
    
    # Second pass - exclude entries containing the top OSD from first pass
    if sorted_osds:
        top_osd_1 = sorted_osds[0][0]
        secondary_counts = defaultdict(int)
        secondary_entries = []
        
        for entry in osd_entries:
            if top_osd_1 not in entry:
                secondary_entries.append(entry)
                for osd in entry:
                    secondary_counts[osd] += 1
        
        if secondary_counts:
            print("\n[Secondary Analysis] Excluding entries with top OSD (osd.{})".format(top_osd_1))
            print("{:<8} {:<8} {:<20}".format("OSD", "Count", "Host"))
            print("-" * 40)
            
            # Sort secondary OSDs by count
            sorted_secondary = sorted(secondary_counts.items(), key=lambda x: x[1], reverse=True)
            
            for osd, count in sorted_secondary:
                host = osd_to_host.get(osd, "Unknown")
                print("{:<8} {:<8} {:<20}".format(f"osd.{osd}", count, host))
            
            # Third pass - exclude entries containing both top OSDs from first and second passes
            if sorted_secondary:
                top_osd_2 = sorted_secondary[0][0]
                third_counts = defaultdict(int)
                
                for entry in secondary_entries:
                    if top_osd_2 not in entry:
                        for osd in entry:
                            third_counts[osd] += 1
                
                if third_counts:
                    print("\n[Third Analysis] Excluding entries with top 2 OSDs (osd.{} and osd.{})".format(top_osd_1, top_osd_2))
                    print("{:<8} {:<8} {:<20}".format("OSD", "Count", "Host"))
                    print("-" * 40)
                    
                    # Sort third OSDs by count
                    sorted_third = sorted(third_counts.items(), key=lambda x: x[1], reverse=True)
                    
                    for osd, count in sorted_third:
                        host = osd_to_host.get(osd, "Unknown")
                        print("{:<8} {:<8} {:<20}".format(f"osd.{osd}", count, host))
                else:
                    print("\nNo third OSDs found after excluding entries containing the top 2 OSDs.")
        else:
            print("\nNo secondary OSDs found after excluding entries containing the top OSD.")

def main():
    log_file, osd_tree_file, pid, latency_threshold = parse_args()
    
    # Parse the log file to get OSD counts and all entries
    osd_counts, osd_entries = parse_log_file(log_file, pid, latency_threshold)
    
    # Parse the OSD tree file to get OSD to host mapping
    osd_to_host = parse_osd_tree(osd_tree_file)
    
    # Print the results
    print_results(osd_counts, osd_entries, osd_to_host)

if __name__ == "__main__":
    main()
