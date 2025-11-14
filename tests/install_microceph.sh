#!/bin/bash

set -xe

# Names of the 3 nodes that form the microceph cluster
NODES=("node1" "node2" "node3")

# Install and setup lxc nodes for use in microceph
setup_lxd() {
snap install lxd --classic

lxd init --preseed <<EOF
config:
  core.https_address: ''
storage_pools:
- name: default
  driver: zfs
  config:
    size: 15GiB
networks:
- name: lxdbr0
  type: bridge
  config: {}
profiles:
- name: default
  devices:
    root:
      type: disk
      path: /
      pool: default
    eth0:
      type: nic
      network: lxdbr0
      name: eth0
EOF

for node in "${NODES[@]}"; do
    echo "Creating LXD container $node..."
    lxc launch ubuntu:noble $node
done

# Wait for containers to start
sleep 30

lxc list
}

# Helper to run lxc cmds
lxd_exec() {
    lxc exec "$1" -- bash -c "$2"
}

main() {

setup_lxd

# Prepare all nodes: install microceph snap, disable swap, set hostname inside containers
for node in "${NODES[@]}"; do
  echo "Preparing $node..."
  lxd_exec $node "hostnamectl set-hostname $node"
  lxd_exec $node "swapoff -a"
  lxd_exec $node "snap install microceph --edge"
  lxd_exec $node "snap refresh --hold microceph"
done

# Bootstrap the cluster on node1
echo "Bootstrapping cluster on node1..."
lxd_exec node1 "microceph cluster bootstrap"

# Generate join tokens on node1 for other nodes
TOKEN_NODE2=$(lxd_exec node1 "microceph cluster add node2")
TOKEN_NODE3=$(lxd_exec node1 "microceph cluster add node3")

echo "Tokens for joining cluster:"
echo "node2: $TOKEN_NODE2"
echo "node3: $TOKEN_NODE3"

# Join node2 and node3 to the cluster
lxd_exec node2 "microceph cluster join $TOKEN_NODE2"
lxd_exec node3 "microceph cluster join $TOKEN_NODE3"

# Add storage using loop files inside each container (3x 3G files per node)
for node in "${NODES[@]}"; do
  echo "Adding 3 loop-file backed OSDs in $node..."
  lxd_exec $node "microceph disk add loop,2G,3"
done

# Check status on node1
echo "Cluster status from node1:"
lxd_exec node1 "microceph status"
}

main "$@"

