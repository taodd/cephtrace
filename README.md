# Cephtrace 
cephtrace is a project contains various eBPF based ceph tracing tool, those tools can be used to trace different ceph components dynamically, without the need to restart or reconfig any ceph services, currently radostrace, osdtrace are implemented.

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
./radostrace

## Run osdtrace:
./osdtrace

## Note:
Can run fine on Ubuntu Jammy 22.04 and 20.04 with 5.15 kernel, other platform hasn't been tested.
Not been tested for container-based process yet. 
