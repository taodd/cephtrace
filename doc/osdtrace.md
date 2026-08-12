# osdtrace

**osdtrace** is an eBPF-based tool for tracing Ceph OSD operations with detailed latency breakdown across multiple processing stages. It provides deep visibility into OSD performance from network message receipt through bluestore backend completion.

## Overview

osdtrace attaches to ceph-osd processes and traces operations with latency breakdown across:
- **Messenger layer:** Network throttling, receive, and dispatch
- **OSD processing layer:** Queue wait, request processing, replication coordination
- **BlueStore backend:** Transaction preparation, I/O wait, commit

This multi-layer visibility helps pinpoint exactly where latency is occurring in the OSD stack.

### Use Cases

Run osdtrace on **Ceph OSD nodes** to:
- Identify which stage of processing is causing latency
- Diagnose slow operations (slow ops in Ceph logs)
- Understand replication latency to peer OSDs
- Monitor per-io BlueStore performance metrics(kv_commit, aio_wait, read_onode_meta_lat, bluestore_clist_lat...)
- Analyze queue depth and scheduling issues
- Troubleshoot network vs storage bottlenecks

### What You Can Learn

- Latency distribution across messenger, OSD, and BlueStore layers
- Eaxct time spent waiting on each peer OSD for replication
- Detailed blueStore internal latencies
- Queue depth and processing delays on PG layer(Able to print operations stalled on waiting for scrub, waiting for peered or some other background OSD activities)
- Able to inspect the difference between Client-to-Primary vs Primary-to-Secondary operation

## Quick Start

### With Pre-built Binary (Ubuntu)

osdtrace ships with DWARF data for many Ceph releases **compiled into the binary**
(keyed by the `ceph-osd` ELF build-id), so for covered versions no DWARF download
or debug symbols are needed:

```bash
# Download osdtrace
wget https://github.com/taodd/cephtrace/releases/latest/download/osdtrace
chmod +x osdtrace

# Discover the OSDs on this host and whether they are traceable as-is
sudo ./osdtrace --list
#  PID        OSD ID     Container    Traceable   Ceph Version
#  -----------------------------------------------------------------------
#  4373       0          yes          yes         19.2.3-0ubuntu0.24.04.3

# Trace one OSD by ID
sudo ./osdtrace --id 0

# Or trace every traceable ceph-osd on the host
sudo ./osdtrace -a
```

Use `./osdtrace --list-embedded` to see all Ceph versions with compiled-in DWARF
data. If your version is not embedded, fall back to a DWARF JSON file (`-i`) or
debug symbols (below).

### With a DWARF JSON File

```bash
# Check your ceph-osd version
dpkg -l | grep ceph-osd

# Download matching DWARF file
wget https://raw.githubusercontent.com/taodd/cephtrace/main/files/ubuntu/osdtrace/osd-17.2.9-0ubuntu0.22.04.3_dwarf.json

# Start tracing
sudo ./osdtrace -i osd-17.2.9-0ubuntu0.22.04.3_dwarf.json
```

### With Debug Symbols Installed (when no matching DWARF JSON file)

```bash
# Install debug symbols
sudo apt-get install ceph-osd-dbgsym

# Run osdtrace (parses DWARF from the installed binary at startup)
sudo ./osdtrace
```

## Command-Line Options

```
-p <pid1,pid2,...>         Probe using process IDs (comma-separated; mandatory
                           for tracing containerized processes by PID)
--id <osd-id1,osd-id2,...> Probe by OSD ID (comma-separated; resolves to PIDs
                           via automatic discovery)
-a, --all                  Trace ALL traceable ceph-osd processes on the host
                           (native and containerized)
-t <seconds>               Set execution timeout in seconds
-s                         Single OP probe mode (logs PrimaryLogPG::log_op_stats
                           only - lower overhead, one line per op)
-b                         Bluestore probe mode: log each BlueStore::log_latency
                           / log_latency_fn call as "bluestore <name> lat <us>",
                           where <name> is the operation label the OSD passes
                           (e.g. _txc_committed_kv, kv_commit, _do_read, _remove)
-l <milliseconds>          Only capture operations slower than this threshold
-i <filename>              Import DWARF info from JSON file
-j <filename>              Export DWARF info to JSON file and exit
--skip-version-check       Skip version check when importing DWARF JSON
                           (needed when host/container package versions differ)
--list                     List active ceph-osd processes (PID, OSD ID,
                           container status, traceability, version) and exit
--list-embedded            List Ceph versions with DWARF data compiled into
                           this binary and exit
-V, --version              Print version information and exit
-h                         Show help message
```

By default osdtrace runs in **full tracing mode**, printing the complete latency
breakdown (messenger, OSD, peers, BlueStore sub-latencies) for every operation.
The former `-x` flag is gone - its output is now the default; the `-d` and `-m`
aggregation options were removed at the same time.

### Examples

#### Discover OSDs, then trace by OSD ID
```bash
sudo ./osdtrace --list
sudo ./osdtrace --id 3          # one OSD
sudo ./osdtrace --id 3,5,7      # several OSDs
```

#### Trace all traceable OSDs on the host
```bash
sudo ./osdtrace -a
```

#### Trace specific PIDs
```bash
sudo ./osdtrace -p 12345
sudo ./osdtrace -p 12345,12399
```

#### Only show slow operations
```bash
# Capture only ops slower than 50 ms
sudo ./osdtrace --id 0 -l 50
```

#### Low-overhead single-line mode
```bash
sudo ./osdtrace --id 0 -s
```

#### Trace for a limited time
```bash
# Trace for 60 seconds then exit
sudo ./osdtrace --id 0 -t 60
```

#### Use DWARF JSON file
```bash
sudo ./osdtrace -i /path/to/osdtrace_dwarf.json
```

#### Generate DWARF JSON file
```bash
# Requires debug symbols installed
sudo ./osdtrace -j osdtrace_dwarf.json
```

#### Trace containerized OSD
```bash
# Discover containerized OSDs (Container column = yes)
sudo ./osdtrace --list

# Embedded DWARF data is matched by build-id even inside containers,
# so for covered versions this just works:
sudo ./osdtrace --id 2

# For versions without embedded data, import a JSON matching the
# *container's* Ceph version and skip the host version check:
sudo ./osdtrace -p 12345 -i dwarf.json --skip-version-check
```

## Output Format

### Example Output

```
osd 1 pg 20.138 op_r size 8192 client 169954691 tid 150680 object benchmark_data_host_3093113_object10 osd_ops [read] throttle_lat 2 recv_lat 11 dispatch_lat 12 queue_lat 41 osd_lat 35 bluestore_lat 231 op_lat 332
osd 38 pg 20.14f op_r size 4096 client 169954691 tid 150884 object benchmark_data_host_3093113_object47 osd_ops [read] throttle_lat 2 recv_lat 10 dispatch_lat 12 queue_lat 45 osd_lat 40 bluestore_lat 334 op_lat 443
osd 38 pg 20.16b op_w size 12288 client 179589331 tid 24057 object benchmark_data_host_3093113_object52 osd_ops [write] throttle_lat 2 recv_lat 26 dispatch_lat 15 queue_lat 57 osd_lat 187 peers [(34, 8079), (40, 5065)] bluestore_lat 10639 (prepare 107 aio_wait 0 (aio_size 0) seq_wait 6 kv_commit 10525) op_lat 10966
osd 38 pg 20.0 subop_w size 17067 client 179589331 tid 24056 object benchmark_data_host_3093113_object52 txn_ops [write,setattrs] throttle_lat 0 recv_lat 56 dispatch_lat 12 queue_lat 42 osd_lat 50 bluestore_lat 11737 (prepare 68 aio_wait 0 (aio_size 0) seq_wait 8 kv_commit 11660) subop_lat 11943
osd 1 pg 164.2 subop_w size 780 client 174758496 tid 4640511 object - txn_ops [touch,write] throttle_lat 0 recv_lat 4 dispatch_lat 2 queue_lat 160 osd_lat 25 bluestore_lat 2988 (prepare 31 aio_wait 0 (aio_size 0) seq_wait 7 kv_commit 2949) subop_lat 3301
```

### Operation Types

Each operation is labeled by type:

| Type | Description | Direction |
|------|-------------|-----------|
| **op_r** | Read operation | Client → Primary OSD |
| **op_w** | Write operation | Client → Primary OSD |
| **subop_w** | Sub-write operation | Primary OSD → Replica OSDs |

An op counts as a write when the primary built an ObjectStore transaction for
it, not when it carried a payload. Class methods that only touch omap — RGW's
`rgw.bucket_prepare_op`, `rgw.obj_remove` and friends — therefore show up as
`op_w size 0`, matching the `subop_w` rows they produce on the replicas.

### Field Descriptions

| Field | Description | Unit | Present In |
|-------|-------------|------|------------|
| **osd** | OSD ID | - | All ops |
| **pg** | Placement group | pool.pg | All ops |
| **op_r/op_w/subop_w** | Operation type | - | All ops |
| **size** | Operation data size | bytes | All ops |
| **client** | Client global ID | - | All ops |
| **tid** | Client request Transaction ID | - | All ops |
| **object** | Target object name (`-` when unavailable; truncated to 63 bytes, unsafe bytes percent-encoded) | - | All ops |
| **osd_ops** | Decoded client `CEPH_OSD_OP_*` names (up to 8, with truncation count) | - | op_r, op_w |
| **txn_ops** | Replica `ObjectStore::Transaction::OP_*` names (up to 8, with truncation count) | - | subop_w |
| **throttle_lat** | Message throttling delay | μs | All ops |
| **recv_lat** | Message receive time | μs | All ops |
| **dispatch_lat** | Dispatch to OSD layer | μs | All ops |
| **queue_lat** | OSD op Queue time | μs | All ops |
| **osd_lat** | OSD processing time | μs | All ops |
| **peers** | Replica wait times | [(osd, μs), ...] | op_w only |
| **bluestore_lat** | Total BlueStore time | μs | All ops |
| **prepare** | Transaction prep | μs | Write ops |
| **aio_wait** | Async I/O wait | μs | Write ops |
| **aio_size** | Async I/O size | bytes | Write ops |
| **seq_wait** | Sequencer wait | μs | Write ops |
| **kv_commit** | KV store commit | μs | Write ops |
| **op_lat / subop_lat** | Total end-to-end latency | μs | All ops |

Note:
1. All latencies are measured in **microseconds (μs)**.
2. op_lat/subop_lat is not a simple sum of all above sub stage latencies, they measure the time when the operation 
first entered into the OSD to the time when OSD has done processing and reply to the client or primary OSD.

## Understanding Latency Breakdown

Let's analyze a write operation in detail:

```
osd 38 pg 20.16b op_w size 12288 client 179589331 tid 24057 object benchmark_data_host_3093113_object52 osd_ops [write] throttle_lat 2 recv_lat 26 dispatch_lat 15 queue_lat 57 osd_lat 187 peers [(34, 8079), (40, 5065)] bluestore_lat 10639 (prepare 107 aio_wait 0 (aio_size 0) seq_wait 6 kv_commit 10525) op_lat 10966
```

### Stage-by-Stage Breakdown

#### 1. Messenger Layer (Network)

**throttle_lat: 2μs**
- Flow control throttling to prevent message queue overload
- Low values (< 10μs) are normal
- High values indicate backpressure/overload

**recv_lat: 26μs**
- Time to receive complete message from network
- First byte to last byte
- Affected by network bandwidth and message size

**dispatch_lat: 15μs**
- Internal message routing from messenger to OSD layer
- Usually very low (< 50μs)

**Total Messenger: ~43μs**

#### 2. OSD Processing Layer

**queue_lat: 57μs**
- Time waiting in OSD operation shard queue
- High values indicate OSD CPU saturation or queue backlog
- Each OSD has multiple shards for parallelism

**osd_lat: 187μs**
- Client request verification
- Authorization checks
- Replication coordination
- Sending sub-operations to replicas

**peers: [(34, 8079), (40, 5065)]**
- OSD 34 took 8079μs (8.079ms) to respond
- OSD 40 took 5065μs (5.065ms) to respond
- Primary waits for all replicas before acknowledging to client
- The slowest replica determines replication latency

**Total OSD Processing: ~244μs + waiting for replicas**

#### 3. BlueStore Layer (Storage)

**bluestore_lat: 10639μs (10.6ms)** - Total BlueStore processing

For write operations this is broken down into:

**prepare: 107μs**
- Transaction preparation
- Allocating space, building write operations
- Generally low overhead

**aio_wait: 0μs**
- Async I/O completion wait time
- Time waiting for disk I/O (for data writes)
- aio_size: 0 bytes (no deferred writes in this case)

**seq_wait: 6μs**
- Sequencer wait time
- Ordering needed for concurrent operations happens on same PG
- Usually very low

**kv_commit: 10525μs (10.5ms)**
- Flush data to main device and metadata to rocksdb
- **Often the dominant latency component**
- Affected by disk performance, write amplification, compaction

**Total BlueStore: 10.6ms** (dominated by kv_commit)

#### 4. Total Operation Latency

**op_lat: 10966μs (11ms)**
- End to end latency

Since replication happens in parallel with local storage, the total includes the maximum of (local bluestore time, replica wait time).

## Interpreting Results

#### Network Bottleneck
```
throttle_lat 5000 recv_lat 120000 dispatch_lat 20 ...
```
- High throttle_lat: Message queue overload
- High recv_lat: Network bandwidth saturation
- **Solution:** Check network utilization, MTU settings, NIC offloads

#### Storage Bottleneck
```
osd_lat 50 bluestore_lat 2500000 (prepare 100 aio_wait 0 kv_commit 2480000) ...
```
- High bluestore_lat, especially kv_commit
- **Solution:** Check disk performance, reduce write amplification, tune RocksDB

#### Replication Issues
```
osd_lat 100 peers [(5, 5000), (10, 48000)] bluestore_lat 2000 ...
```
- Peer osd.10 have much higher latency than local bluestore and peer osd.5
- **Solution:** Check osd.10's performance, and network between the current tracing OSD to osd.10

### Read vs Write Patterns

**Reads (op_r):**
- No replication overhead
- Lower latency if data is cached
- BlueStore read path is generally faster

**Writes (op_w):**
- Must replicate to all OSDs in acting set
- Must wait for all replicas (slowest determines latency)
- BlueStore must commit to RocksDB (kv_commit)

**Sub-writes (subop_w):**
- Replica-side writes
- No further replication
- Still must commit to local BlueStore

## Common Usage Scenarios

### Scenario 1: Diagnosing Slow Ops

```bash
# Trace every traceable OSD on the host; only capture ops slower than 10 ms
sudo ./osdtrace -a -l 10 > /tmp/osdtrace.log

# Let it run during slow ops, then analyze
# Look for patterns in the latency breakdown
```

### Scenario 2: Monitoring Specific OSD

```bash
# Trace a specific OSD that's showing issues
sudo ./osdtrace --id 5 -t 300 > osd5_trace.log
```

### Scenario 3: Comparing Primary vs Replica Performance

```bash
# Trace all OSDs, then filter
sudo ./osdtrace -a > full_trace.log

# Analyze primary operations (op_r, op_w)
grep -E "op_r|op_w" full_trace.log > primary_ops.log

# Analyze replica operations (subop_w)
grep "subop_w" full_trace.log > replica_ops.log

# Compare average latencies
```

## osdtrace log analyzer
- [Analysis Tools](analyze-osdtrace.md) - Automated analysis scripts

## Man Page

For detailed command-line reference:
```bash
man osdtrace
```

Or see: [osdtrace.8](man/8/osdtrace.rst)
