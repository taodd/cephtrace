#!/bin/bash

# This test is meant to be run after building osdtrace and radostrace.
# This generates new dwarf files and compares to the respective
# reference dwarf files in the repository.
# This version is for CentOS Stream.

set -ex

# Install the ceph package
dnf install -y centos-release-ceph-reef
dnf install -y ceph-common

# Install debug symbols, needed to generate dwarf.json
dnf install -y ceph-debuginfo ceph-osd-debuginfo librados-devel librados-debuginfo librbd-devel

# Get the ceph version for reference file lookup
matching_ref_version=$(rpm -q ceph-common --queryformat '%{VERSION}-%{RELEASE}')

# Test osdtrace dwarf json generation
echo "Testing osdtrace dwarf json generation..."
osd_new_dwarf="generated-osd-dwarf.json"
./osdtrace -j $osd_new_dwarf
osd_ref_file="./files/centos-stream/osdtrace/osd-${matching_ref_version}_dwarf.json"
diff $osd_ref_file $osd_new_dwarf
echo "osdtrace dwarf json comparison passed!"

# Test radostrace dwarf json generation
echo "Testing radostrace dwarf json generation..."
rados_new_dwarf="generated-rados-dwarf.json"
./radostrace -j $rados_new_dwarf
rados_ref_file="./files/centos-stream/radostrace/${matching_ref_version}_dwarf.json"
diff $rados_ref_file $rados_new_dwarf
echo "radostrace dwarf json comparison passed!"

echo "All dwarf json comparisons passed successfully!"
