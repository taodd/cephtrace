# radostrace

**radostrace** is an eBPF-based tool for tracing librados-based Ceph client operations in real-time. It provides detailed per-IO performance metrics without requiring any Ceph service restarts or configuration changes.

## Overview

radostrace attaches to librados client processes and traces every operation sent to the Ceph cluster, capturing:
- Which process and client is performing the operation
- Target pool, placement group (PG), and OSD acting set
- Operation type (read/write), size, offset, length, and latency
- Object name and detailed OSDOp type 

### Use Cases

Run radostrace on machines acting as Ceph clients:
- **Virtual machines** with Ceph RBD volumes attached
- **OpenStack services** (Cinder volume service, Glance image service)
- **RGW gateway servers** (RADOS Gateway)
- **Custom applications** using librados libraries
- **Kubernetes nodes** with RBD persistent volumes

### What You Can Learn

- Identify slow I/O operations and those OSDs contributed to the high latency IOs
- Quickly pinpoint the underperformed OSDs in the cluster (refer [Analysis Tools](analyze-radostrace.md))
- Understand I/O patterns (random vs sequential, read vs write, 4k aligned or unaligned IO)
- Monitor object-level access pattern

## Quick Start

### With Pre-built Binary and DWARF File (Ubuntu)

```bash
# Download radostrace
wget https://github.com/taodd/cephtrace/releases/latest/download/radostrace
chmod +x radostrace

# Check your librados version
dpkg -l | grep librados

# Download matching DWARF file
wget https://raw.githubusercontent.com/taodd/cephtrace/main/files/ubuntu/radostrace/17.2.6-0ubuntu0.22.04.2_dwarf.json

# Start tracing all librados clients
sudo ./radostrace -i 17.2.6-0ubuntu0.22.04.2_dwarf.json
```

### With Debug Symbols Installed

```bash
# Install debug symbols
sudo apt-get install librados2-dbgsym librbd1-dbgsym

# Run radostrace (will auto-parse DWARF data)
sudo ./radostrace
```

## Command-Line Options

### Basic Options

```
-p, --pid <PID>          Trace specific process ID only
-t, --time <seconds>     Run for specified duration then exit
-i, --import <file>      Import DWARF data from JSON file
-j, --json <file>        Export DWARF data to JSON file and exit
--skip-version-check     Skip version compatibility check when importing
-h, --help              Show help message
```

### Examples

#### Trace all librados clients
```bash
sudo ./radostrace
```

#### Trace a specific process
```bash
# Find the process ID for a VM
ps aux | grep qemu-system

# Trace that specific VM
sudo ./radostrace -p 12345
```

#### Trace for a limited time
```bash
# Trace for 60 seconds then exit
sudo ./radostrace -t 60
```

#### Use DWARF JSON file
```bash
sudo ./radostrace -i /path/to/radostrace_dwarf.json
```

#### Generate DWARF JSON file
```bash
# Requires debug symbols installed
sudo ./radostrace -j radostrace_dwarf.json
```

#### Trace containerized process
```bash
# Find the process ID on the host
ps aux | grep ceph-client

# Skip version check for container mismatch
sudo ./radostrace -p 12345 -i dwarf.json --skip-version-check
```

## Output Format

### Example Output

```
     pid  client     tid  pool  pg     acting            w/r    size  latency     object[ops][offset,length]
   19015   34206  419357     2  1e     [1,11,121,77,0]     W        0     887     rbd_header.374de3730ad0[watch ]
   19015   34206  419358     2  1e     [1,11,121,77,0]     W        0    8561     rbd_header.374de3730ad0[call ]
   19015   34206  419359     2  39     [0,121,11,77,1]     R     4096    1240     rbd_data.374de3730ad0.0000000000000000[read ][0, 4096]
   19015   34206  419360     2  39     [0,121,11,77,1]     R     4096    1705     rbd_data.374de3730ad0.0000000000000000[read ][4096, 4096]
   19015   34206  419361     2  39     [0,121,11,77,1]     R     4096    1334     rbd_data.374de3730ad0.0000000000000000[read ][12288, 4096]
   19015   34206  419362     2  2b     [77,11,1,0,121]     R     4096    2180     rbd_data.374de3730ad0.00000000000000ff[read ][4128768, 4096]
```

### Column Descriptions

Each row represents one I/O operation sent from the client to the Ceph cluster:

| Column | Description | Example | Notes |
|--------|-------------|---------|-------|
| **pid** | Client process ID | 19015 | The Linux process ID of the application |
| **client** | Ceph client global ID | 34206 | Unique identifier assigned by the Ceph cluster |
| **tid** | Transaction/operation ID | 419357 | Incrementing counter for each operation |
| **pool** | Pool ID | 2 | Numeric ID of the target pool |
| **pg** | Placement group ID | 1e | Combined with pool forms full PG (2.1e) |
| **acting** | OSD acting set | [1,11,121,77,0] | OSDs handling this PG (primary first) |
| **w/r** | Operation type | R or W | Read (R) or Write (W) |
| **size** | Operation size in bytes | 4096 | Data size being read/written (0 for metadata ops) |
| **latency** | Operation latency | 1240 | End-to-end latency in microseconds (μs) |
| **object** | Object name and operations | rbd_data....[read][0, 4096] | Object name, operation type, offset, length |

### Understanding the Output

#### Operation Types
- **Read (R):** Data read from the cluster
- **Write (W):** Data written to the cluster

#### Special Operations
Operations with size 0 are typically metadata operations:
- `watch` - RBD image watch operation (for change notifications)
- `call` - Class method calls (e.g., RBD header operations)
- `stat` - Object stat operations
- `create` - Object creation

#### Acting Set
The first OSD in the acting set is the **primary OSD**. The client sends all operations to the primary, which then coordinates with replicas.

Example: `[1,11,121,77,0]`
- Primary OSD: 1
- Replica OSDs: 11, 121, 77, 0

#### Latency Analysis
Latency values are in **microseconds (μs)**:
- `1000 μs` = 1 millisecond (ms)
- `1000000 μs` = 1 second (s)

Typical latencies:
- **Good:** < 1000 μs (< 1ms) for SSD-backed pools
- **Moderate:** 1000-5000 μs (1-5ms)
- **Concerning:** > 10000 μs (> 10ms)
- **Poor:** > 100000 μs (> 100ms)

#### Object Name Patterns

**RBD volumes:**
- Header: `rbd_header.<image_id>`
- Data: `rbd_data.<image_id>.<object_number>`

**RGW objects:**
- Various patterns depending on object type
- Shadow objects, multipart uploads, etc.

**CephFS data:**
- `<inode_number>.<object_sequence>`

### Interpreting Results

#### Example 1: Sequential Read Workload
```
   19015   34206  100001     2  39     [0,121,11]     R     4096    1200     rbd_data.abc.0000000000000000[read][0, 4096]
   19015   34206  100002     2  39     [0,121,11]     R     4096    1150     rbd_data.abc.0000000000000000[read][4096, 4096]
   19015   34206  100003     2  39     [0,121,11]     R     4096    1180     rbd_data.abc.0000000000000000[read][8192, 4096]
```
- Same object, sequential offsets (0, 4096, 8192)
- Consistent low latencies (~1.2ms)
- Good performance

#### Example 2: Random Read with Hot Spot
```
   19015   34206  100001     2  39     [0,121,11]     R     4096     500     rbd_data.abc.000000000000001f[read][16384, 4096]
   19015   34206  100002     2  2a     [5,99,33]      R     4096   120000     rbd_data.abc.0000000000000042[read][0, 4096]
   19015   34206  100003     2  39     [0,121,11]     R     4096     520     rbd_data.abc.000000000000001f[read][20480, 4096]
```
- Object `1f` has low latency (~500μs) - likely cached
- Object `42` has high latency (120ms) - possible slow disk or PG issue
- Different PGs have different performance

#### Example 3: Write Operations
```
   19015   34206  200001     2  1a     [10,22,33]     W    65536    8500     rbd_data.xyz.0000000000000010[write][0, 65536]
```
- 64KB write (65536 bytes)
- 8.5ms latency
- Must replicate to all OSDs in acting set

## Common Usage Scenarios

### Scenario 1: Troubleshooting Slow VM

```bash
# On the host that the VM is running
sudo ./radostrace -p <pid of the vm> -i <dwarf_json> -t 300 > /tmp/radostrace_output.txt

# Look for operations with high latency (over 100ms) values
awk '$9 > 100000' /tmp/radostrace_output.txt
```

### Scenario 2: Monitoring OpenStack Cinder

```bash
# Find Cinder volume service process
ps aux | grep cinder-volume

# Trace that specific process
sudo ./radostrace -p <PID> -i <dwarf_json>
```

### Scenario 3: Analyzing RGW traffic 

```bash
# Trace RGW gateway
sudo ./radostrace -p $(pgrep radosgw) -t 300 > rgw_trace.log

# Analyze object access patterns later
# Look for frequently accessed objects, large transfers, etc.
```

## Man Page

For detailed command-line reference:
```bash
man radostrace
```
Or see: [radostrace.8](man/8/radostrace.rst)

## See Also
- [Analysis Tools](analyze-radostrace.md) - Automated analysis scripts
