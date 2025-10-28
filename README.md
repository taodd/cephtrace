# Cephtrace
```cephtrace``` is a project that delivers various ```eBPF``` based ceph tracing tools. These tools can be used to trace different ceph components dynamically, without the need to restart or reconfigure any of the ceph related services. Currently ```radostrace``` and ```osdtrace``` have been implemented.

These tools can provide a great insight on the per-io based performance, and help to quickly identify any potential performance bottlenecks.

> 💡 **New to CephTrace?** Ubuntu users can try it immediately with our [Quick Start](#-quick-start-ubuntu-only) (no installation needed), or [build from source](#️-build-from-source) for other systems.

## 🚀 Quick Start 

**Try CephTrace in 30 seconds - no installation, no debug symbols, no compilation!**

For Ubuntu users, we provide pre-built binaries and DWARF data files for immediate use:

### radostrace
**radostrace** traces librados-based Ceph clients in real-time, showing detailed per-IO performance metrics. Run it on machines holding Ceph clients like:
- vms with ceph rbd volumes attached
- openstack Cinder and Glance services
- RGW gateway servers
- Any application using librados/librbd

### Step 1: Download Pre-built Binary
```bash
# Download the latest radostrace binary
wget https://github.com/taodd/cephtrace/releases/latest/download/radostrace
chmod +x radostrace
```

### Step 2: Download DWARF Data for Your Ceph Version
```bash
# Check your Ceph version
dpkg -l | grep librados

# Download corresponding DWARF file (example for Ceph 17.2.6-0ubuntu0.22.04.2)
wget https://raw.githubusercontent.com/taodd/cephtrace/main/files/radostrace/17.2.6-0ubuntu0.22.04.2_dwarf.json
```

### Step 3: Start Tracing Immediately
```bash
# Trace all librados clients using pre-built data
sudo ./radostrace -i 17.2.6-0ubuntu0.22.04.2_dwarf.json
```

### osdtrace
**osdtrace** traces OSD operations directly on Ceph storage nodes, providing detailed latency breakdowns from messenger to bluestore level. Run it on:
- Ceph OSD nodes

```bash
# Download osdtrace binary
wget https://github.com/taodd/cephtrace/releases/latest/download/osdtrace
chmod +x osdtrace

# Check your ceph-osd version
dpkg -l | grep ceph-osd

# Download corresponding DWARF file for osdtrace (example for Ceph 17.2.6)
wget https://raw.githubusercontent.com/taodd/cephtrace/main/files/osdtrace/17.2.6-0ubuntu0.22.04.2_dwarf.json

# Start tracing OSD operations
sudo ./osdtrace -i 17.2.6-0ubuntu0.22.04.2_dwarf.json -x
```

> 📋 **Available DWARF Files:** Check the `files/ubuntu/radostrace/` and `files/ubuntu/osdtrace/` directories for your specific Ceph version
> 🐧 **Ubuntu Support:** Currently available for Ubuntu 20.04, 22.04, and 24.04
> ⚡ **Zero Dependencies:** No need to install debug symbols or build dependencies

### Tracing Processes in cephadm deployed CentOS Stream Containers

When tracing Ceph processes running inside CentOS Stream containers, you need to specify the process ID and skip version checking since the binary runs on the host while the traced process runs in the container.

#### radostrace for CentOS Stream Containers

```bash
# Download radostrace binary
wget https://github.com/taodd/cephtrace/releases/latest/download/radostrace
chmod +x radostrace

# Download DWARF file for CentOS Stream 9 (Ceph 19.2.3)
wget https://raw.githubusercontent.com/taodd/cephtrace/main/files/centos-stream/radostrace/rados-2:19.2.3-0.el9_dwarf.json

# Find the process ID of the ceph client process on the host
# Note: Use the actual ceph client process ID, not the container process ID
ps aux | grep <client process name>

# Trace the process with -p flag and --skip-version-check
sudo ./radostrace -i rados-2:19.2.3-0.el9_dwarf.json -p <PID> --skip-version-check
```

#### osdtrace for CentOS Stream Containers

```bash
# Download osdtrace binary
wget https://github.com/taodd/cephtrace/releases/latest/download/osdtrace
chmod +x osdtrace

# Download DWARF file for CentOS Stream 9 (Ceph 19.2.3)
wget https://raw.githubusercontent.com/taodd/cephtrace/main/files/centos-stream/osdtrace/osd-2:19.2.3-0.el9_dwarf.json

# Find the ceph-osd process ID on the host
# Note: Use the actual ceph-osd process ID, not the container process ID
ps aux | grep ceph-osd

# Trace the OSD process with -p flag and --skip-version-check
sudo ./osdtrace -i osd-2:19.2.3-0.el9_dwarf.json -p <PID> --skip-version-check -x
```

> 📦 **CentOS Stream Support:** Currently only version 19.2.3's DWARF JSON file is pre-generated for CentOS Stream. We plan to cover more versions in the future.
> 🔧 **Other Versions:** If you need to trace a different Ceph version, you can generate your own DWARF JSON file by following the [Dwarf json file](#dwarf-json-file) section on a CentOS Stream machine with the target Ceph package version and debug symbols installed.
> ⚠️ **Important:** When tracing containerized processes, use the actual ceph/ceph-osd process ID from the host, not the container process ID.

---

## 🛠️ Build from Source

For non-Ubuntu systems or if you want to build from source:

### Checkout source code
```bash
git clone https://github.com/taodd/cephtrace
cd cephtrace
git submodule update --init --recursive
```

### Build Prerequisites
On a Debian or Ubuntu based system, use the following apt command to start the build dependencies. If using a system with a different package manager, a different set of commands will be required:
```
sudo apt-get install g++ clang libelf-dev libc6-dev-i386 libdw-dev
```

## Build cephtrace
Build the binaries:
```
cd cephtrace
make
```
It is possible to build the binaries on a different machine and then transfer them to the target host and run.

## Install debug symbols
Debug symbols are required for these tools to work if you don't have a pre-generated dwarf json file for the target version. Each tool needs different debug symbol package. For ubuntu, we now support fetching debug symbols from ```debuginfod``` server automatically.

Please install ```libdebuginfod``` package first:
```
sudo apt-get install libdebuginfod-dev
```
You can also manually install debug packages, please refer (for ubuntu) to [Getting dbgsymddeb Packages](https://ubuntu.com/server/docs/debug-symbol-packages#getting-dbgsymddeb-packages).
These are required debug packages for each tool:
- For ```radostrace```:
```sudo apt-get install librbd1-dbgsym librados2-dbgsym```
- For ```osdtrace```:
```sudo apt-get install ceph-osd-dbgsym```

## Dwarf json file
To avoid the need to install debug symbols on every target machine, you can export the DWARF information to a JSON file on a machine with debug symbols installed, then import it on other machines with the same Ceph version.

### Step 1: Export DWARF Information (on a machine with debug symbols)
First, export the DWARF information for your specific Ceph version:

```bash
# Export DWARF info for radostrace
sudo ./radostrace -j radostrace_dwarf.json
```

This will create JSON files containing all the necessary DWARF information with version information embedded.

### Step 2: Import and Use on Target Machines
On any machine with the same Ceph version (but without debug symbols), you can import the JSON file:

```bash
# Use radostrace with imported DWARF data
sudo ./radostrace -i radostrace_dwarf.json
```

### Version Compatibility
The tools automatically check version compatibility when importing JSON files. If the target machine has a different Ceph version than what the JSON file was generated for, the tool will report an error and exit.

### Benefits
- **No debug symbols required** on target machines
- **Faster startup** (no DWARF parsing needed)
- **Consistent results** across machines with the same Ceph version
- **Easy deployment** in production environments

### Pre-generated JSON Files
We provide pre-generated JSON files for common Ceph versions in the `files/ubuntu/radostrace`, `files/ubuntu/osdtrace`, `files/centos-stream/radostrace`, and `files/centos-stream/osdtrace` directories. These files are named with their corresponding version (e.g., `17.2.6-0ubuntu0.22.04.2_dwarf.json` for Ubuntu, `rados-2:19.2.3-0.el9_dwarf.json` for CentOS Stream).

## Radostrace output
Below is an example tracing output from a virtual machine performing 4k random read on a rbd volume:
```
     pid  client     tid  pool  pg     acting            w/r    size  latency     object[ops][offset,length]
   19015   34206  419357     2  1e     [1,11,121,77,0]     W        0     887     rbd_header.374de3730ad0[watch ]
   19015   34206  419358     2  1e     [1,11,121,77,0]     W        0    8561     rbd_header.374de3730ad0[call ]
   19015   34206  419359     2  39     [0,121,11,77,1]     R     4096    1240     rbd_data.374de3730ad0.0000000000000000[read ][0, 4096]
   19015   34206  419360     2  39     [0,121,11,77,1]     R     4096    1705     rbd_data.374de3730ad0.0000000000000000[read ][4096, 4096]
   19015   34206  419361     2  39     [0,121,11,77,1]     R     4096    1334     rbd_data.374de3730ad0.0000000000000000[read ][12288, 4096]
   19015   34206  419362     2  2b     [77,11,1,0,121]     R     4096    2180     rbd_data.374de3730ad0.00000000000000ff[read ][4128768, 4096]
   19015   34206  419363     2  2b     [77,11,1,0,121]     R     4096     857     rbd_data.374de3730ad0.00000000000000ff[read ][4186112, 4096]
   19015   34206  419364     2  2b     [77,11,1,0,121]     R     4096     717     rbd_data.374de3730ad0.00000000000000ff[read ][4190208, 4096]
   19015   34206  419365     2  2b     [77,11,1,0,121]     R     4096     499     rbd_data.374de3730ad0.00000000000000ff[read ][4059136, 4096]
   19015   34206  419366     2  2b     [77,11,1,0,121]     R     4096    1315     rbd_data.374de3730ad0.00000000000000ff[read ][4161536, 4096]
   ...
   ...
```
Each row represent one IO sent from the client to the ceph cluster, below is the explanation for each column:
- ```pid```:    ceph client process id
- ```client```: ceph client global id, a unique number to identify the client
- ```tid```:    operation id
- ```pool```:   pool id the operation is sent to
- ```pg```:     pg id the operation is sent to, pool.pg is the pgid we usually refer to
- ```acting```: the OSD acting set this operation is sent to
- ```w/r```:    whether this operation is write or read
- ```size```:   the write/read size of this operation
- ```latency```: the latency of this request in microsecond
- ```object[ops][offset,length]```: the object name, detailed osd op name, op's offset and length

## osdtrace output
Below is an example tracing output from an OSD node:
```
osd 1 pg 20.138 op_r size 8192 client 169954691 tid 150680 throttle_lat 2 recv_lat 11 dispatch_lat 12 queue_lat 41 osd_lat 35 bluestore_lat 231 op_lat 332
osd 38 pg 20.14f op_r size 4096 client 169954691 tid 150884 throttle_lat 2 recv_lat 10 dispatch_lat 12 queue_lat 45 osd_lat 40 bluestore_lat 334 op_lat 443
osd 38 pg 20.16b op_w size 12288 client 179589331 tid 24057 throttle_lat 2 recv_lat 26 dispatch_lat 15 queue_lat 57 osd_lat 187 peers [(34, 8079), (40, 5065)] bluestore_lat 10639 (prepare 107 aio_wait 0 (aio_size 0) seq_wait 6 kv_commit 10525) op_lat 10966
osd 38 pg 20.0 subop_w size 17067 client 179589331 tid 24056 throttle_lat 0 recv_lat 56 dispatch_lat 12 queue_lat 42 osd_lat 50 bluestore_lat 11737 (prepare 68 aio_wait 0 (aio_size 0) seq_wait 8 kv_commit 11660) subop_lat 11943
osd 1 pg 164.2 subop_w size 780 client 174758496 tid 4640511 throttle_lat 0 recv_lat 4 dispatch_lat 2 queue_lat 160 osd_lat 25 bluestore_lat 2988 (prepare 31 aio_wait 0 (aio_size 0) seq_wait 7 kv_commit 2949) subop_lat 3301
```

Each row represents one operation traced on the OSD, with detailed latency breakdown across different stages:

### Operation Types
- ```op_r```: **Read operation** from client to primary OSD
- ```op_w```: **Write operation** from client to primary OSD
- ```subop_w```: **Sub-write operation** from primary OSD to secondary OSDs (replication)

### Latency Stages (using op_w as example)
Taking the write operation: `osd 38 pg 20.16b op_w size 12288 client 179589331 tid 24057 throttle_lat 2 recv_lat 26 dispatch_lat 15 queue_lat 57 osd_lat 187 peers [(34, 8079), (40, 5065)] bluestore_lat 10639 (prepare 107 aio_wait 0 (aio_size 0) seq_wait 6 kv_commit 10525) op_lat 10966`

#### Messenger Level (Network/Message Processing):
- ```throttle_lat 2```: Flow control throttling time (2μs) - prevents message overload
- ```recv_lat 26```: Message receive time (26μs) from first to last byte - network processing
- ```dispatch_lat 15```: Message dispatch time (15μs) - internal dispatch from messenger to OSD Processing level

#### OSD Processing Level:
- ```queue_lat 57```: Time waiting in osd op shard queue (57μs) - queuing delay before handling
- ```osd_lat 187```: OSD layer processing time (187μs) - client request verification and replication coordination
- ```peers [(34, 8079), (40, 5065)]```: Time spent on waiting from secondary OSDs 34 and 40

#### Storage Backend Level (BlueStore):
- ```bluestore_lat 10639```: Total BlueStore processing time (10639μs)
  - ```prepare 107```: Transaction preparation (107μs)
  - ```aio_wait 0```: Async I/O wait time (0μs)
  - ```seq_wait 6```: Sequencer wait time (6μs)
  - ```kv_commit 10525```: Key-value store commit (10525μs) - data and metadata persistence

#### Total:
- ```op_lat 10966```: **End-to-end operation latency** (10966μs)

All latencies are measured in **microseconds (μs)**.

## Kernel Requirements
- The minimum kernel version required is v5.8
