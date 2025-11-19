# Radostrace Analysis Tool

The `analyze_radostrace_output.py` script provides automated analysis of radostrace log files to identify problematic OSDs involved in high-latency operations.

## Overview

This Python tool parses radostrace output and:
- Identifies operations above a latency threshold
- Counts which OSDs are involved in slow operations
- Maps OSDs to their physical hosts (using OSD tree)
- Highlights problematic OSDs and hosts

## Usage

### Basic Syntax

```bash
./tools/analyze_radostrace_output.py <log_file> <osd_tree_file> [latency_threshold]
```

### Examples

#### Example 1: Basic Analysis

```bash
# Capture radostrace output
sudo ./radostrace -t 300 > radostrace.log

# Get OSD tree
ceph osd tree  > osd_tree

# Analyze (default 100ms threshold)
./tools/analyze_radostrace_output.py radostrace.log osd_tree
```


### Sample Output

```
/home/ubuntu/cephtrace-demo# ./analyze_radostrace_output.sh ./radostrace.log.2 osdtree 
Analyzing log file: ./radostrace.log.2
OSD tree file: osdtree
Latency threshold: 100000 microseconds (100.0 ms)

======================================================================
Starting iterative analysis to identify problematic OSDs...
======================================================================
[Iteration 1] Top OSD: osd.6 (29 occurrences on ip-172-31-25-243)
[Iteration 2] Top OSD: osd.8 (22 occurrences on ip-172-31-25-243)
[Iteration 3] Top OSD: osd.7 (17 occurrences on ip-172-31-25-243)
[Iteration 4] Top OSD: osd.11 (15 occurrences on ip-172-31-25-243)
[Iteration 5] Top OSD: osd.9 (9 occurrences on ip-172-31-25-243)
[Iteration 6] Top OSD: osd.10 (6 occurrences on ip-172-31-25-243)

[Iteration 7] No more high-latency operations found.

======================================================================
=== SUMMARY: Problematic OSDs Identified ===
======================================================================
Rank   OSD        Count    Host                 Iteration 
----------------------------------------------------------------------
1      osd.6      29       ip-172-31-25-243     1         
2      osd.8      22       ip-172-31-25-243     2         
3      osd.7      17       ip-172-31-25-243     3         
4      osd.11     15       ip-172-31-25-243     4         
5      osd.9      9        ip-172-31-25-243     5         
6      osd.10     6        ip-172-31-25-243     6         
----------------------------------------------------------------------
Total problematic OSDs identified: 6
Total high-latency operations analyzed: 98

```

Above example shows all OSDs involved into slow operations are from the same host.
It strongly indicates there is a host-level issue on that specific host, for example,
resource shortage(cpu low performance setting, memory shortage), Network card problem, 
or even shared disk issue if all OSDs share same DB devices or cache device.

### Interpreting Results

**Specific OSD:**
- single or few OSDs appears in many slow operations
- Likely indicates OSD-specific issue (disk, running into specific bug)
- Priority for investigation

**Specific host:**
- Multiple OSDs on same host having issues
- Suggests host-level problem (NIC, kernel, hardware)
- May need host-level troubleshooting

**Distributed issues:**
- Slow ops spread across many OSDs/hosts
- Might indicate cluster-wide issue (network, configuration)
- Less likely to be hardware failure

## See Also
- [radostrace Documentation](radostrace.md) - Radostrace usage guide
- [osdtrace Analysis](analyze-osdtrace.md) - Analyzing OSD-level traces
