# kfstrace

**kfstrace** is an eBPF-based tool for tracing Ceph kernel client operations using kprobes. It provides visibility into CephFS metadata operations (MDS) and data operations (OSD) originating from the kernel client module.

## Overview

kfstrace attaches to kernel functions in the Ceph client module (`ceph.ko`) and traces:
- **MDS operations:** File/directory metadata operations (lookup, create, setattr, etc.)
- **OSD operations:** Data read/write operations to OSDs
- **Both modes:** Complete visibility into kernel client activity

Unlike radostrace and osdtrace, **kfstrace doesn't require DWARF files or debug symbols** - it uses kernel probes that work with the running kernel module.

### Use Cases

Run kfstrace on machines using Ceph kernel clients:
- **CephFS mounts** (kernel-based filesystem mounts)
- **Kernel RBD clients** (rbd kernel module)
- **Any system** using the Ceph kernel client module

### What You Can Learn

- **MDS operations:** File system metadata performance, directory traversal patterns
- **OSD operations:** Data I/O patterns from kernel clients
- **Latency analysis:** Unsafe vs safe reply times from MDS
- **Retry patterns:** Number of attempts for operations
- **Operation results:** Success/failure status for each operation

### Key Advantages

- **No DWARF files needed** - works out of the box
- **No debug symbols required** - simplified deployment
- **Dual-mode operation** - trace OSD, MDS, or both simultaneously
- **Kernel-level visibility** - see exactly what the kernel is doing

## Quick Start

### Basic Usage (No Prerequisites!)

```bash
# Download kfstrace
wget https://github.com/taodd/cephtrace/releases/latest/download/kfstrace
chmod +x kfstrace

# Trace MDS operations (default mode)
sudo ./kfstrace

# Trace OSD operations only
sudo ./kfstrace -m osd

# Trace both OSD and MDS operations
sudo ./kfstrace -m all
```

## Command-Line Options

### Basic Options

```
-m, --mode <mode>        Tracing mode: mds (default), osd, or all
-t, --time <seconds>     Run for specified duration then exit
-l, --latency <us>       Only show operations with latency >= threshold
-h, --help              Show help message
```

### Modes

| Mode | Description | Output |
|------|-------------|--------|
| **mds** | Trace MDS metadata operations only (default) | Filesystem operations |
| **osd** | Trace OSD data operations only | Read/write operations |
| **all** | Trace both MDS and OSD operations | Combined output |

### Examples

#### Trace MDS operations (default)
```bash
sudo ./kfstrace
```

#### Trace OSD operations
```bash
sudo ./kfstrace -m osd
```

#### Trace both OSD and MDS
```bash
sudo ./kfstrace -m all
```

#### Trace for 60 seconds
```bash
sudo ./kfstrace -t 60
```

#### Only show slow operations (>= 1ms)
```bash
sudo ./kfstrace -l 1000
```

#### Trace OSD ops slower than 5ms for 2 minutes
```bash
sudo ./kfstrace -m osd -l 5000 -t 120
```

## Output Formats

kfstrace has two different output formats depending on the mode:

### MDS Mode Output

```
TIME     PID      COMMAND      CLIENT_ID  TID              MDS OP       FILE                  ATTEMPTS UNSAFE_LAT SAFE_LAT   RESULT
14:25:10 9012     ls           4323       9876543          0   lookup   documents             1        -          234μs      OK
14:25:10 9012     ls           4323       9876544          0   readdir  files                 1        -          456μs      OK
14:25:11 3456     touch        4324       9876545          0   create   newfile.txt           1        512μs      1.2ms      OK
14:25:12 7890     vim          4325       9876546          1   setattr  document.txt          1        -          345μs      OK
14:25:13 2345     rm           4326       9876547          0   unlink   oldfile               1        678μs      2.3ms      OK
14:25:14 5678     mv           4327       9876548          0   rename   file1                 1        890μs      3.1ms      OK
```

#### MDS Column Descriptions

| Column | Description | Example | Notes |
|--------|-------------|---------|-------|
| **TIME** | Completion timestamp | 14:25:10 | HH:MM:SS format |
| **PID** | Process ID | 9012 | Linux process performing the operation |
| **COMMAND** | Process name | ls | Truncated to 12 characters |
| **CLIENT_ID** | Ceph client global ID | 4323 | Unique client identifier |
| **TID** | Client request transaction ID | 9876543 | Operation ID |
| **MDS** | Target MDS rank | 0 | Which MDS is handling this operation |
| **OP** | Operation type | lookup | See MDS Operations table below |
| **FILE** | Request file | filename | Truncated to 32 chars if too long |
| **ATTEMPTS** | Retry count | 1 | Number of send attempts |
| **UNSAFE_LAT** | Unsafe reply latency | 512μs | Time to fast acknowledgment (writes only) before MDS submit the metadata change to journal |
| **SAFE_LAT** | Safe reply latency | 1.2ms | Time to durable acknowledgment after metadata change is persistent in journal|
| **RESULT** | Operation result | OK or ERR | Success or error |

#### MDS Operations

Common MDS operation types:

| Operation | Description | Typical Use |
|-----------|-------------|-------------|
| **lookup** | Path/name lookup | Resolving filenames to inodes |
| **getattr** | Get file attributes | ls, stat commands |
| **setattr** | Set file attributes | chmod, chown, touch |
| **readdir** | Read directory entries | ls directory listing |
| **open** | Open file | File open operations |
| **create** | Create new file | Creating files |
| **unlink** | Delete file | Removing files |
| **rename** | Rename/move file | mv command |
| **mkdir** | Create directory | mkdir command |
| **rmdir** | Remove directory | rmdir command |
| **symlink** | Create symbolic link | ln -s command |
| **link** | Create hard link | ln command |

#### Understanding MDS Two-Phase Replies

MDS uses a two-phase protocol for write operations:

**1. Unsafe Reply (fast acknowledgment)**
- MDS has received and processed the request
- Changes are in MDS memory
- Not yet persisted to journal
- Unblock the client

**2. Safe Reply (durable acknowledgment)**
- Changes committed to MDS journal
- Guaranteed durable even if MDS crashes
- Slower due to journal I/O

**Read-only operations** (lookup, getattr, readdir) only have safe replies, so UNSAFE_LAT shows "-".

**Latency interpretation:**
```
create   newfile.txt   1   512μs   1.2ms   OK
```
- Unsafe: 512μs - MDS acknowledged creation to unblock the client
- Safe: 1.2ms - MDS committed to journal

### OSD Mode Output

```
TIME     PID      COMMAND      CLIENT_ID  TID              POOL     PG       OP     ACTING_SET           OBJECT                           ATTEMPTS OPS                            LATENCY(us)
14:23:45 1234     fio          4321       1234567          1        2a       READ   [0,1,2]              rbd_data.12345.000000001         1        [read(0,4096)]                 456μs
14:23:45 1234     fio          4321       1234568          1        2a       WRITE  [0,1,2]              rbd_data.12345.000000001         1        [write(4096,8192)]             1234μs
14:23:46 5678     dd           4322       1234569          2        3b       READ   [3,4,5]              rbd_data.67890.000000010         1        [read(0,131072)]               892μs
```

#### OSD Column Descriptions

| Column | Description | Example | Notes |
|--------|-------------|---------|-------|
| **TIME** | Completion timestamp | 14:23:45 | HH:MM:SS format |
| **PID** | Process ID | 1234 | Linux process performing I/O |
| **COMMAND** | Process name | fio | Truncated to 12 characters |
| **CLIENT_ID** | Ceph client global ID | 4321 | Unique client identifier |
| **TID** | Transaction ID | 1234567 | Operation ID |
| **POOL** | Pool ID | 1 | Target pool for the operation |
| **PG** | Placement group | 2a | Combined with pool: 1.2a |
| **OP** | Operation type | READ, WRITE | See below |
| **ACTING_SET** | OSD acting set | [0,1,2] | Primary OSD first |
| **OBJECT** | Object name | rbd_data.12345.000000001 | Target object |
| **ATTEMPTS** | Retry count | 1 | Number of send attempts |
| **OPS** | Detailed OSD ops | [read(0,4096)] | Operation with offset, length |
| **LATENCY(us)** | End-to-end latency | 456μs | Microseconds |

#### Detailed OPS Field

The OPS column shows individual OSD operations:

```
[read(0,4096)]                    # Single 4KB read at offset 0
[write(4096,8192)]                # Single 8KB write at offset 4096
[call(rbd.parent_get)]            # Class method call
```

## Common Usage Scenarios

### Scenario 1: Diagnosing Slow CephFS Performance

```bash
# Trace MDS operations for slow filesystem
sudo ./kfstrace -t 300 > /tmp/mds_trace.log

# Find slow operations
awk '$9 > 100000' /tmp/mds_trace.log

# Or use latency filter
sudo ./kfstrace -l 100000  # Show ops >= 10ms
```

### Scenario 2: Analyzing File Access Patterns

```bash
# Trace for a period
sudo ./kfstrace -m mds -t 60 > access_pattern.log

# Count operation types
awk '{print $7}' access_pattern.log | sort | uniq -c | sort -rn

# Most accessed files
awk '{print $8}' access_pattern.log | sort | uniq -c | sort -rn | head -20
```

### Scenario 3: Monitoring Kernel RBD Performance

```bash
# Trace OSD operations from kernel RBD
sudo ./kfstrace -m osd

# With latency threshold for slow I/Os
sudo ./kfstrace -m osd -l 100000  # >= 100ms
```

## Interpreting Results

### Healthy MDS Performance

```
14:25:10 9012  ls      4323  9876543  0  lookup   /data/files  1  -      120μs   OK
14:25:10 9012  ls      4323  9876544  0  readdir  /data/files  1  -      234μs   OK
```
- Low latencies (< 1ms)
- Single attempt (no retries)
- Successful results

### Good OSD Performance

```
14:23:45 1234  fio  4321  1234567  1  2a  READ  [0,1,2]  rbd_data.abc  1  [read(0,4096)]  450μs
```
- Sub-millisecond latency
- Single attempt
- **Result:** Healthy OSD performance

### Slow OSD Storage

```
14:23:46 1234  fio  4321  1234568  1  2a  WRITE  [0,1,2]  rbd_data.abc  1  [write(0,65536)]  450ms
```
- 450ms latency for writing 64KB data
- **Issue:** Check Primary OSD 0 with osdtrace 

### Distinguishing Kernel vs FUSE Client

kfstrace only works with **kernel** Ceph clients, not FUSE (ceph-fuse).

**Check your mount type:**
```bash
mount | grep ceph
```

**Kernel mount:**
```
192.168.1.1:6789:/ on /mnt/cephfs type ceph (rw,relatime,name=admin,...)
```

**FUSE mount (kfstrace won't work):**
```
ceph-fuse on /mnt/cephfs type fuse.ceph-fuse (rw,nosuid,nodev,...)
```

## Comparison with Other Tools

| Feature | kfstrace | radostrace | osdtrace |
|---------|----------|------------|----------|
| **Target** | Kernel clients | Librados clients | OSD processes |
| **DWARF files/Debug symbols** | ❌ Not needed | ✅ Required | ✅ Required |
| **MDS ops** | ✅ Yes | ❌ No | ❌ No |
| **OSD ops** | ✅ Yes | ✅ Yes | ✅ Yes (server-side) |

**When to use kfstrace:**
- Tracing CephFS clients (especially for metadata operations)
- Kernel RBD clients
- Quick troubleshooting (no setup needed)
- Don't have debug symbols available

**When to use radostrace:**
- Userspace librados clients
- RGW, OpenStack services
- More detailed client-side information needed

**When to use osdtrace:**
- OSD-level diagnostics
- Detailed latency breakdown needed
- Investigating slow ops at the OSD side 

## Man Page

For detailed command-line reference:
```bash
man kfstrace
```

Or see: [kfstrace.8](../man/8/kfstrace.rst)
