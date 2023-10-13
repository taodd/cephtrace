Clone:
git clone https://github.com/taodd/cephtrace

git submodule update --init --recursive

Prerequisite packages:
sudo apt-get install clang libelf-dev libc6-dev-i386 libdw-dev
sudo apt-get install ceph-osd-dbgsym //Refer https://wiki.ubuntu.com/Debug%20Symbol%20Packages to Enable dbgsym repo  

Build:
1. cd cephtrace
2. make

Start to trace your OSD op's latency:
./osdtrace -x

Note:
Can run fine on Ubuntu Jammy 22.04 and 20.04 with 5.15 kernel, other platform hasn't been tested.
Not been tested for container-based ceph-osd process yet. 
