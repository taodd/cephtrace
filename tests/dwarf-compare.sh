#!/bin/bash

# This test is meant to be run after building osdtrace and radostrace.
# This generates new dwarf files and compares to the respective
# reference dwarf files in the repository.

set -ex

# Install the ceph package
sudo apt update
sudo apt install ceph-common -y

# Install debug symbols, needed to generate dwarf.json
sudo apt install ubuntu-dbgsym-keyring -y

echo "Types: deb
URIs: http://ddebs.ubuntu.com/
Suites: $(lsb_release -cs) $(lsb_release -cs)-updates
Components: main restricted universe multiverse
Signed-by: /usr/share/keyrings/ubuntu-dbgsym-keyring.gpg" | \
sudo tee -a /etc/apt/sources.list.d/ddebs.sources

sudo apt update
sudo apt install ceph-osd-dbgsym librados2-dbgsym librbd1-dbgsym -y

# Get the ceph version for reference file lookup
matching_ref_version=$(dpkg -l | awk '$2=="ceph-common" {print $3}')

# Test osdtrace dwarf json generation
echo "Testing osdtrace dwarf json generation..."
osd_new_dwarf="generated-osd-dwarf.json"
./osdtrace -j $osd_new_dwarf
osd_ref_file="./files/ubuntu/osdtrace/osd-${matching_ref_version}_dwarf.json"
./tests/compare_dwarf_json.py $osd_ref_file $osd_new_dwarf
echo "osdtrace dwarf json comparison passed!"

# Test radostrace dwarf json generation
echo "Testing radostrace dwarf json generation..."
rados_new_dwarf="generated-rados-dwarf.json"
./radostrace -j $rados_new_dwarf
rados_ref_file="./files/ubuntu/radostrace/${matching_ref_version}_dwarf.json"
./tests/compare_dwarf_json.py $rados_ref_file $rados_new_dwarf
echo "radostrace dwarf json comparison passed!"

echo "All dwarf json comparisons passed successfully!"
