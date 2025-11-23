#!/bin/bash

# This test is meant to be run after building osdtrace and radostrace.
# This generates new dwarf files and compares to the respective
# reference dwarf files in the repository.
# This version is for CentOS Stream.

set -ex

# Install the ceph package
curl --silent --remote-name --location https://download.ceph.com/rpm-squid/el9/noarch/cephadm
chmod +x cephadm
./cephadm add-repo --version 19.2.3

# Install ceph packages and debug symbols, needed to generate dwarf.json
dnf install -y ceph-osd ceph-osd-debuginfo librados2 librbd1 librados2-debuginfo librbd1-debuginfo

# Get the ceph version for reference file lookup
matching_ref_version=$(rpm -q ceph-osd --queryformat '%{EPOCH}:%{VERSION}-%{RELEASE}')

# Test osdtrace dwarf json generation
echo "Testing osdtrace dwarf json generation..."
osd_new_dwarf="generated-osd-dwarf.json"
./osdtrace -j $osd_new_dwarf
osd_ref_file="./files/centos-stream/osdtrace/osd-${matching_ref_version}_dwarf.json"
./tests/compare_dwarf_json.py $osd_ref_file $osd_new_dwarf
echo "osdtrace dwarf json comparison passed!"

# Test radostrace dwarf json generation
echo "Testing radostrace dwarf json generation..."
rados_new_dwarf="generated-rados-dwarf.json"
./radostrace -j $rados_new_dwarf
rados_ref_file="./files/centos-stream/radostrace/rados-${matching_ref_version}_dwarf.json"
./tests/compare_dwarf_json.py $rados_ref_file $rados_new_dwarf
echo "radostrace dwarf json comparison passed!"

echo "All dwarf json comparisons passed successfully!"
