# Cephtrace 
```cephtrace``` is a project that delivers various ```eBPF``` based ceph tracing tools. These tools can be used to trace different ceph components dynamically, without the need to restart or reconfigure any of the ceph related services. Currently ```radostrace``` and ```osdtrace``` have been implemented.

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
```radostrace``` can trace any librados based ceph client, including vm with rbd volume attached, rgw, cinder, glance...

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
```

Below is an example for tracing a vm which is doing 4k random read on a rbd volume:
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
```
:~$ sudo ./osdtrace -x
```

## Kernel requirement
- The minimum kernel version required is v5.8  
