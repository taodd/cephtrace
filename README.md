# Cephtrace 
```cephtrace``` is a project that delivers various ```eBPF``` based ceph tracing tools. These tools can be used to trace different ceph components dynamically, without the need to restart or reconfigure any of the ceph related services. Currently ```radostrace```, ```osdtrace```, and ```kfstrace``` have been implemented.

These tools can provide a great insight on the per-io based performance, and help to quickly identify any potential performance bottlenecks.

## Checkout source code
To start:
```
git clone https://github.com/taodd/cephtrace
cd cephtrace
git submodule update --init --recursive
```

## Build Prerequisites
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
It is possible to build the binaries on a different machine and then transfer them to the target host, as long as they are running the same versions of underlying packages as the builder machine.

## Install debug symbols
Debug symbols are required for these tools to work. Each tool needs a different debug symbol package. For ubuntu, we now support fetching debug symbols from ```debuginfod``` server automatically.

Please install ```libdebuginfod``` package first:
```
sudo apt-get install libdebuginfod-dev
```
You can also manually install debug packages in case debuginfod isn't working, please refer to [Getting dbgsymddeb Packages](https://ubuntu.com/server/docs/debug-symbol-packages#getting-dbgsymddeb-packages).
These are required debug packages for each tool:
- For ```radostrace```:
```sudo apt-get install librbd1-dbgsym librados2-dbgsym```
- For ```osdtrace```:
```sudo apt-get install ceph-osd-dbgsym```

## Using JSON Export/Import for Easy Deployment
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
We provide pre-generated JSON files for Common Ceph versions in the `files/radostrace/` directory. These files are named with their corresponding version (e.g., `17.2.6-0ubuntu0.22.04.2_dwarf.json`).

#### Example: Using a Pre-generated JSON File

To use a specific version, download the corresponding JSON file and run radostrace with it:

```bash
# Download a specific version JSON file
wget https://raw.githubusercontent.com/taodd/cephtrace/main/files/radostrace/17.2.6-0ubuntu0.22.04.2_dwarf.json

# Run radostrace with the downloaded JSON file
sudo ./radostrace -i 17.2.6-0ubuntu0.22.04.2_dwarf.json
```

## Run radostrace
`radostrace` can trace any librados based ceph client, including virtual machines using rbd backed volumes attached, rgw, cinder and glance.

### Basic Usage
```
:~$ sudo ./radostrace   # By default trace all processes(based on librados) on the host
```

### Advanced Options
```
:~$ sudo ./radostrace -p <pid>          # Trace only the specified process ID
:~$ sudo ./radostrace -t <seconds>      # Set execution timeout
:~$ sudo ./radostrace -j <file>         # Export DWARF info to JSON file
:~$ sudo ./radostrace -i <file>         # Import DWARF info from JSON file
:~$ sudo ./radostrace -o <file>         # Export events data info to CSV (default: radostrace_events.csv)
```

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

## Run osdtrace
`osdtrace` can probe and trace OSD(s) directly on given nodes. This utility does not yet properly support using DWARF files, hence requires the debugging symbol packages being available on the target node.

### Basic Usage ()
```
:~$ sudo ./osdtrace -x
```

### Advanced Options
```
:~$ sudo ./osdtrace -d <seconds>       # Set probe duration in seconds to calculate average latency
:~$ sudo ./osdtrace -m <avg|max>       # Set operation latency collection mode
:~$ sudo ./osdtrace -l <milliseconds>  # Set operation latency threshold to capture
:~$ sudo ./osdtrace -o <od-id>         # Only probe a specific OSD
:~$ sudo ./osdtrace -x                 # Set probe mode to Full OPs. See below for details.
:~$ sudo ./osdtrace -b                 # Set probe mode to Bluestore. See below for details.
:~$ sudo ./osdtrace -j <file>          # Export DWARF info to JSON file
:~$ sudo ./osdtrace -i <file>          # Import DWARF info from JSON file
:~$ sudo ./osdtrace -t <seconds>       # Set execution timeout in seconds
:~$ sudo ./osdtrace -p <pid>           # Probe using a Process ID
:~$ sudo ./osdtrace -h                 # Show this help message
```

Below is an example tracing output from an OSD node:
```
osd 1 pg 20.138 op_r size 8192 client 169954691 tid 150680 throttle_lat 2 recv_lat 11 dispatch_lat 12 queue_lat 41 osd_lat 35 bluestore_lat 231 op_lat 332
osd 38 pg 20.80 op_r size 4096 client 169954691 tid 150732 throttle_lat 1 recv_lat 11 dispatch_lat 14 queue_lat 40 osd_lat 43 bluestore_lat 29 op_lat 139
osd 1 pg 20.135 op_r size 4096 client 169954691 tid 150790 throttle_lat 2 recv_lat 13 dispatch_lat 15 queue_lat 81 osd_lat 47 bluestore_lat 27 op_lat 185
osd 38 pg 20.14f op_r size 4096 client 169954691 tid 150847 throttle_lat 1 recv_lat 13 dispatch_lat 13 queue_lat 46 osd_lat 47 bluestore_lat 322 op_lat 442
osd 1 pg 20.135 op_r size 4096 client 169954691 tid 150863 throttle_lat 2 recv_lat 14 dispatch_lat 14 queue_lat 56 osd_lat 41 bluestore_lat 336 op_lat 462
osd 38 pg 20.14f op_r size 4096 client 169954691 tid 150884 throttle_lat 2 recv_lat 10 dispatch_lat 12 queue_lat 45 osd_lat 40 bluestore_lat 334 op_lat 443
osd 38 pg 20.16b op_w size 12288 client 179589331 tid 24057 throttle_lat 2 recv_lat 26 dispatch_lat 15 queue_lat 57 osd_lat 187 peers [(34, 8079), (40, 5065)] bluestore_lat 10639 (prepare 107 aio_wait 0 (aio_size 0) seq_wait 6 kv_commit 10525) op_lat 10966
osd 38 pg 20.0 subop_w size 17067 client 179589331 tid 24056 throttle_lat 0 recv_lat 56 dispatch_lat 12 queue_lat 42 osd_lat 50 bluestore_lat 11737 (prepare 68 aio_wait 0 (aio_size 0) seq_wait 8 kv_commit 11660) subop_lat 11943
osd 38 pg 20.0 subop_w size 4779 client 179589331 tid 24058 throttle_lat 0 recv_lat 23 dispatch_lat 9 queue_lat 55 osd_lat 51 bluestore_lat 1842 (prepare 60 aio_wait 0 (aio_size 0) seq_wait 6 kv_commit 1775) subop_lat 2016
osd 1 pg 20.183 subop_w size 4779 client 179589331 tid 24059 throttle_lat 2 recv_lat 21 dispatch_lat 15 queue_lat 47 osd_lat 77 bluestore_lat 10746 (prepare 83 aio_wait 0 (aio_size 0) seq_wait 9 kv_commit 10653) subop_lat 10951
osd 1 pg 164.2 subop_w size 780 client 174758496 tid 4640437 throttle_lat 2 recv_lat 18 dispatch_lat 17 queue_lat 80 osd_lat 669 bluestore_lat 8961 (prepare 136 aio_wait 0 (aio_size 0) seq_wait 6 kv_commit 8818) subop_lat 9781
osd 1 pg 164.2 subop_w size 782 client 174758496 tid 4640439 throttle_lat 1 recv_lat 18 dispatch_lat 12 queue_lat 63 osd_lat 72 bluestore_lat 8311 (prepare 56 aio_wait 0 (aio_size 0) seq_wait 9 kv_commit 8245) subop_lat 8531
osd 1 pg 164.2 subop_w size 782 client 174758496 tid 4640440 throttle_lat 1 recv_lat 18 dispatch_lat 14 queue_lat 66 osd_lat 66 bluestore_lat 3773 (prepare 59 aio_wait 0 (aio_size 0) seq_wait 7 kv_commit 3707) subop_lat 4020
osd 1 pg 164.2 subop_w size 782 client 174758496 tid 4640443 throttle_lat 1 recv_lat 15 dispatch_lat 16 queue_lat 59 osd_lat 75 bluestore_lat 1389 (prepare 60 aio_wait 0 (aio_size 0) seq_wait 8 kv_commit 1320) subop_lat 1603
osd 1 pg 164.2 subop_w size 782 client 174758496 tid 4640489 throttle_lat 1 recv_lat 15 dispatch_lat 14 queue_lat 90 osd_lat 74 bluestore_lat 1127 (prepare 51 aio_wait 0 (aio_size 0) seq_wait 6 kv_commit 1069) subop_lat 1360
osd 1 pg 164.2 subop_w size 782 client 174758496 tid 4640492 throttle_lat 2 recv_lat 13 dispatch_lat 14 queue_lat 64 osd_lat 59 bluestore_lat 1494 (prepare 47 aio_wait 0 (aio_size 0) seq_wait 6 kv_commit 1441) subop_lat 1685
osd 1 pg 164.2 subop_w size 782 client 174758496 tid 4640500 throttle_lat 2 recv_lat 20 dispatch_lat 14 queue_lat 44 osd_lat 59 bluestore_lat 1323 (prepare 43 aio_wait 0 (aio_size 0) seq_wait 6 kv_commit 1273) subop_lat 1497
osd 1 pg 164.2 subop_w size 782 client 174758496 tid 4640509 throttle_lat 1 recv_lat 16 dispatch_lat 15 queue_lat 48 osd_lat 85 bluestore_lat 2105 (prepare 63 aio_wait 0 (aio_size 0) seq_wait 8 kv_commit 2032) subop_lat 2351
osd 1 pg 164.2 subop_w size 782 client 174758496 tid 4640510 throttle_lat 0 recv_lat 11 dispatch_lat 5 queue_lat 90 osd_lat 34 bluestore_lat 3039 (prepare 35 aio_wait 0 (aio_size 0) seq_wait 7 kv_commit 2996) subop_lat 3283
osd 1 pg 164.2 subop_w size 780 client 174758496 tid 4640511 throttle_lat 0 recv_lat 4 dispatch_lat 2 queue_lat 160 osd_lat 25 bluestore_lat 2988 (prepare 31 aio_wait 0 (aio_size 0) seq_wait 7 kv_commit 2949) subop_lat 3301
```

## Kernel requirement
- The minimum kernel version required is v5.8
