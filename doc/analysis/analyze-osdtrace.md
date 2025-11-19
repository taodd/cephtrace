# Osdtrace Analysis Tool

The `analyze_osdtrace_output.py` script provides automated statistical analysis of osdtrace log files with fio-style latency distribution output.

## Overview

This Python tool parses osdtrace output and provides:
- Statistical analysis (min, max, avg, fio-like percentiles) for latencies
- Per-OSD filtering
- Per-latency-field filtering (analyze specific stages like recv_lat, kv_commit)
- Sorted output for detailed inspection

## Usage

### Basic Syntax

```bash
./tools/analyze_osdtrace_output.py <osdtrace_log> [options]
```

### Options

| Option | Description | Example |
|--------|-------------|---------|
| `-o, --osd <ID>` | Filter by specific OSD ID | `-o 5` |
| `-f, --field <name>` | Analyze specific latency field | `-f recv_lat` |
| `-s, --sort` | Print sorted lines instead of stats | `-s` |
| `-i, --infer` | Print a latency contributions distribution | `-i` |
| `-h, --help` | Show help message | - |

### Available Fields

When using `-f` option, you can analyze these latency components:

**Main latencies:**
- `throttle_lat` - Throttling delay
- `recv_lat` - Message receive time
- `dispatch_lat` - Message dispatch time
- `queue_lat` - Queue wait time
- `bluestore_lat` - Total BlueStore time

**BlueStore sub-latencies** :
- `prepare` - Transaction preparation
- `aio_wait` - Async I/O wait
- `seq_wait` - Sequencer wait
- `kv_commit` - RocksDB commit time

## Examples

### Example 1: Basic Statistical Analysis

```bash
# Capture osdtrace output
sudo ./osdtrace -x -t 300 > osdtrace.log

# Analyze all operations
./tools/analyze_osdtrace_output.py osdtrace.log
```

**Sample output:**
```
osd.11:
  op_r lat (μsec): min=90, max=298, avg=134.67, stdev=25.00, samples=528
  lat percentiles (μsec):
  |   1.00th=[ 97.00],  5.00th=[105.00], 10.00th=[110.00],
  |  20.00th=[116.00], 30.00th=[121.00], 40.00th=[125.00],
  |  50.00th=[130.00], 60.00th=[134.00], 70.00th=[140.00],
  |  80.00th=[150.00], 90.00th=[165.00], 95.00th=[179.00],
  |  99.00th=[220.00], 99.50th=[228.00], 99.90th=[298.00]

  op_w lat (μsec): min=3598, max=7265, avg=4129.62, stdev=311.36, samples=553
  lat percentiles (μsec):
  |   1.00th=[3693.00],  5.00th=[3789.00], 10.00th=[3881.00],
  |  20.00th=[3990.00], 30.00th=[4045.00], 40.00th=[4089.00],
  |  50.00th=[4123.00], 60.00th=[4156.00], 70.00th=[4191.00],
  |  80.00th=[4228.00], 90.00th=[4279.00], 95.00th=[4345.00],
  |  99.00th=[4720.00], 99.50th=[6775.00], 99.90th=[7265.00]

  subop_w lat (μsec): min=2976, max=6437, avg=3275.76, stdev=141.65, samples=1505
  lat percentiles (μsec):
  |   1.00th=[3068.00],  5.00th=[3116.00], 10.00th=[3149.00],
  |  20.00th=[3188.00], 30.00th=[3218.00], 40.00th=[3244.00],
  |  50.00th=[3270.00], 60.00th=[3294.00], 70.00th=[3322.00],
  |  80.00th=[3350.00], 90.00th=[3400.00], 95.00th=[3439.00],
  |  99.00th=[3539.00], 99.50th=[3587.00], 99.90th=[5461.00]

```
### Example 2: Analyze recv_lat (Network Performance)

```bash
# Focus on message receive times
./tools/analyze_osdtrace_output.py osdtrace.log -f recv_lat
```

**What is recv_lat:**
- Total message transmission time from first byte to last byte
- Measures network bandwidth and message processing time
- Includes time to receive the complete message over the network

**Why this is useful:**
- **Large recv_lat is a strong indication of networking issues**
- High values suggest network bandwidth saturation or packet loss
- Helps isolate network problems from storage problems

**Typical values:**
- **Good:** < 50μs for small messages on 10GbE
- **Acceptable:** 50-1000μs depending on message size and network
- **Problem:** > 100ms indicates network issue(usually packet loss, NIC problems)

### Example 3: Analyze kv_commit Latency

```bash
# Focus on RocksDB commit times
./tools/analyze_osdtrace_output.py osdtrace.log -f kv_commit
```

**Why this is useful:**
- kv_commit is often the dominant latency component for writes
- High kv_commit indicates storage backend issues

### Example 4: Combine OSD and Field Filters

```bash
# Combine filters: OSD 22, kv_commit only
./tools/analyze_osdtrace_output.py osdtrace.log -o 22 -f kv_commit
```

Perfect for deep-diving into a specific OSD's storage performance.

### Example 5: Sorted Output for Manual Inspection

```bash
# Get sorted list of kv_commit latencies
./tools/analyze_osdtrace_output.py osdtrace.log -s -f kv_commit

# Filter to find very slow operations slower than
# or equal to 50ms (units are in microseconds)
./tools/analyze_osdtrace_output.py osdtrace.log -s -f kv_commit -t 50000 | tail -20
```

### Example 6: Latency Contribution Distribution

If you are not sure which latency field to start looking into, you can see a high level overview

```bash
./tools/analyze_osdtrace_output.py osdtrace.log -i
```

Sample output:
```console
> ./tools/analyze_osdtrace_output.py tools/sample-logs/osdtrace_data.log -o 6 -i
osd.6:
...
  subop_w:
    65.69% from bluestore_lat
    10.23% from queue_lat
     7.90% from osd_lat
     3.81% from recv_lat
     1.24% from dispatch_lat
     0.02% from throttle_lat
...
```

This drives the investigation towards looking at bluestore latency,
as described in example 1 or 2 (but with `-f bluestore_lat`)


**Sample sorted output:**
```
osd 5 pg 2.3a op_w size 4096 client 12345 tid 67890 ... kv_commit 2340
osd 5 pg 2.3a op_w size 8192 client 12345 tid 67891 ... kv_commit 3120
osd 5 pg 2.3a op_w size 4096 client 12345 tid 67892 ... kv_commit 45670
```

## Workflow Integration

### Step 1: Capture Detailed Trace

```bash
# Use -x for extended BlueStore breakdown
sudo ./osdtrace -x -t 300 > osdtrace-$(date +%Y%m%d-%H%M%S).log
```

### Step 2: Quick Overview of Latency Contributions

```bash
# Get overall contributions
./tools/analyze_osdtrace_output.py osdtrace-*.log -i
```

### Step 3: Quick Overview Analysis

```bash
# Get overall statistics
./tools/analyze_osdtrace_output.py osdtrace-*.log
```

### Step 4: Drill Down by Component

```bash
# Analyze each latency component
for field in queue_lat osd_lat bluestore_lat kv_commit; do
    echo "=== $field ==="
    ./tools/analyze_osdtrace_output.py osdtrace-*.log -f $field
    echo
done
```

## Understanding the Output

### Statistical Metrics

**Min/Max/Avg:**
- Self-explanatory
- Avg can be misleading if there are outliers

**Percentiles:**
- **p50 (median):** Half of operations are slower than this
- **p90:** 10% of operations are slower than this
- **p95:** 5% of operations are slower than this
- **p99:** 1% of operations are slower than this
- **p99.9:** 0.1% of operations are slower than this

**Why percentiles matter:**
- More meaningful than average for understanding real-world performance
- p99 represents "worst case" for most users
- Easy to see whether there are high tail latency
- SLA targets often based on percentiles (e.g., "p95 < 10ms")


### Comparing Before/After Changes

```bash
# Before tuning
sudo ./osdtrace -x -t 300 > before.log
./tools/analyze_osdtrace_output.py before.log -f kv_commit > before-analysis.txt

# Apply tuning (e.g., RocksDB settings)
ceph config set osd bluestore_rocksdb_options "..."

# After tuning
sudo ./osdtrace -x -t 300 > after.log
./tools/analyze_osdtrace_output.py after.log -f kv_commit > after-analysis.txt

# Compare
diff -u before-analysis.txt after-analysis.txt
```
