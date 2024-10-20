# Cephtrace 
cephtrace is a project contains various eBPF based ceph tracing tool, those tools can be used to trace different ceph components dynamically, without the need to restart or reconfig any ceph services, currently radostrace, osdtrace are implemented. These tool can provide us great insight on the per-io performance, and help us quickly identify the performance bottleneck. 

## Checkout source code:
git clone https://github.com/taodd/cephtrace
git submodule update --init --recursive

## Build Prerequisites:
I provide the Debian and Ubuntu apt commands in this procedure. If you use a system with a different package manager, then you will have to use different commands:
sudo apt-get install g++ clang libelf-dev libc6-dev-i386 libdw-dev

## Build cephtrace
- cd cephtrace
- make

## Install debug symbol
Debug symbol is required for those tools to work, different tool need different debug symbol package. For ubuntu, we now support to fetch debug symbols from debuginfod server automatically. Please install libdebuginfod package first: 
sudo apt-get install libdebuginfod-dev

However, if debuginfod not working, you can manually install those required debug packages for each different tool:
- radostrace: sudo apt-get install ceph-common-dbgsym librbd1-dbgsym librados2-dbgsym
- osdtrace: sudo apt-get install ceph-osd-dbgsym

## Run radostrace:
radostrace can trace any librados based ceph client, including vm with rbd volume attached, rgw, cinder, glance ...
below is an example for tracing a vm which is doing 4k random read on a rbd volume.
./radostrace
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
Each row represent one IO sent from the client to the ceph cluster, below is the explaination for each column:
pid:    ceph client process id
client: ceph client global id, a unique number to identify the client
tid:    operation id 
pool:   pool id the operation is sent to
pg:     pg id the operation is sent to, pool.pg is the pgid we usually talked about
acting: the OSD acting set this operation is sent to
w/r:    whether this operation is write or read
size:   the write/read size of this operation
latency: the latency of this request in microsecond
object[ops][offset,length]: the object name, detailed osd op name, op's offset and length

## Run osdtrace:
./osdtrace

## Note:
Can run fine on Ubuntu Jammy 22.04 and 20.04 with 5.15 kernel, other platform hasn't been tested.
Not been tested for container-based process yet. 
