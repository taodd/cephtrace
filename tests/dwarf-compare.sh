#!/bin/bash

# This test is meant to be run after building a new osdtrace.
# This generates a new dwarf file and compares to the respective
# reference dwarf file in the repository.

set -ex

# Install the ceph package
sudo apt update
sudo apt install ceph-common -y

# Install debug symbols, needed to generate dwarf.json
sudo apt install ubuntu-dbgsym-keyring -y

echo "Types: deb
URIs: http://ddebs.ubuntu.com/
Suites: $(lsb_release -cs) $(lsb_release -cs)-updates $(lsb_release -cs)-proposed
Components: main restricted universe multiverse
Signed-by: /usr/share/keyrings/ubuntu-dbgsym-keyring.gpg" | \
sudo tee -a /etc/apt/sources.list.d/ddebs.sources

sudo apt update
sudo apt install ceph-osd-dbgsym -y

# Generate the new dwarf json and compare
new_dwarf="generated-dwarf.json"
./osdtrace -j $new_dwarf
matching_ref_version=$(dpkg -l | awk '$2=="ceph-common" {print $3}')
ref_file="./files/ubuntu/osdtrace/osd-${matching_ref_version}_dwarf.json"
diff $ref_file $new_dwarf
