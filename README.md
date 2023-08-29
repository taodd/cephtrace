Clone:
git clone https://github.com/taodd/cephtrace
git submodule update --init --recursive

Prerequisite packages:
sudo apt-get install clang libelf-dev libc6-dev-i386 libdw-dev
sudo apt-get install ceph-osd-dbgsym //Refer https://wiki.ubuntu.com/Debug%20Symbol%20Packages to Enable dbgsym repo  

Build:
1. cd cephtrace
2. make

Start to trace your osd op's latency:
./osdtrace 

Note:
Can running fine on Ubuntu Jammy 22.04, other platform hasn't been tested.
Also not tested for container based ceph-osd process yet. 
