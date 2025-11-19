# Tracing Containerized Ceph Deployments

When Ceph is deployed using containers (e.g., cephadm, Docker, Podman), tracing requires special considerations since the cephtrace binary runs on the host while the target process runs inside a container.

## Overview

**Key Challenges:**
- Binary runs on host, traced process runs in container
- Process namespaces require PID translation
- DWARF files must match the container's Ceph version, not the host's

**Solutions:**
- Use `--skip-version-check` flag
- Specify exact process ID with `-p`
- Generate or download DWARF files matching container's Ceph version

## cephadm Deployments

cephadm is the recommended Ceph deployment tool that uses containers (typically Podman or Docker).

### Identifying Container Processes

#### Find Client Processes (for radostrace)

```bash
# Find RGW process on host
ps aux | grep radosgw

# Example output:
# root  12345  ... /usr/bin/radosgw -f --cluster ceph ...
```

The PID shown (12345) is the host PID, which is what you'll use with radostrace.

#### Find OSD Processes (for osdtrace)

```bash
# Find ceph-osd processes on host
ps aux | grep ceph-osd

# Example output:
# ceph  23456  ... /usr/bin/ceph-osd -f --cluster ceph --id 0 ...
# ceph  23457  ... /usr/bin/ceph-osd -f --cluster ceph --id 1 ...
```

Each OSD runs as a separate process with a unique PID.

### Determine Container's Ceph Version

```bash
# Check Ceph version in container
cephadm shell -- ceph version

# Or check specific package version
cephadm shell -- rpm -q ceph-osd     # For RHEL-based
cephadm shell -- dpkg -l | grep ceph # For Debian-based
```

### Tracing with CentOS Stream Containers

CentOS Stream is common in cephadm deployments.

#### radostrace for CentOS Stream

```bash
# Download radostrace binary
wget https://github.com/taodd/cephtrace/releases/latest/download/radostrace
chmod +x radostrace

# Download DWARF file matching container's Ceph version
# Example for Ceph 19.2.3 on CentOS Stream 9
wget https://raw.githubusercontent.com/taodd/cephtrace/main/files/centos-stream/radostrace/rados-2:19.2.3-0.el9_dwarf.json

# Find the client process PID on the host
ps aux | grep radosgw

# Trace with --skip-version-check
sudo ./radostrace -i rados-2:19.2.3-0.el9_dwarf.json -p <HOST_PID> --skip-version-check
```

**Why skip version check?**
- The tool checks the host's library version
- Container has different library version
- Version check would fail even though DWARF file is correct for the container

#### osdtrace for CentOS Stream

```bash
# Download osdtrace binary
wget https://github.com/taodd/cephtrace/releases/latest/download/osdtrace
chmod +x osdtrace

# Download DWARF file matching container's Ceph version
wget https://raw.githubusercontent.com/taodd/cephtrace/main/files/centos-stream/osdtrace/osd-2:19.2.3-0.el9_dwarf.json

# Find the ceph-osd process PID on the host
ps aux | grep ceph-osd 

# Trace with --skip-version-check and extended output
sudo ./osdtrace -i osd-2:19.2.3-0.el9_dwarf.json -p <HOST_PID> --skip-version-check -x
```

### Tracing with Ubuntu Containers

If using Ubuntu-based Ceph containers:

```bash
# Determine container's Ubuntu Ceph version
cephadm shell -- dpkg -l | grep librados

# Download matching DWARF file
wget https://raw.githubusercontent.com/taodd/cephtrace/main/files/ubuntu/radostrace/17.2.6-0ubuntu0.22.04.2_dwarf.json

# Trace
sudo ./radostrace -i 17.2.6-0ubuntu0.22.04.2_dwarf.json -p <HOST_PID> --skip-version-check
```

## k8s/rook Deployments
The steps are same with the tracing the cephadm deployed cluster.

## Generating DWARF Files for Containers

If pre-generated DWARF files aren't available for your container's Ceph version:

### Method 1: Generate Inside Container

```bash
# Enter container
docker exec -it ceph-osd-0 /bin/bash

# Inside container, install debug symbols
# For Ubuntu:
apt-get install ceph-osd-dbgsym

# Copy cephtrace binary into container
docker cp ./osdtrace ceph-osd-0:/tmp/

# Generate DWARF file inside container
docker exec ceph-osd-0 /tmp/osdtrace -j /tmp/osd_dwarf.json

# Copy DWARF file out
docker cp ceph-osd-0:/tmp/osd_dwarf.json ./
```

### Method 2: Use Matching Development Environment

```bash
# Set up a VM/Host with same OS and Ceph version as your container
# Install debug symbols
# Run radostrace/osdtrace with -j to generate DWARF JSON

# Copy DWARF file to production host
# Use with --skip-version-check
```

## kfstrace with Containers

**Good news:** kfstrace works normally with containerized Ceph!
**Why?** kfstrace traces the kernel module (`ceph.ko`), not the container processes. The kernel module runs on the host, so there's no container complexity.


## See Also

- [Getting Started Guide](getting-started.md) - Basic installation
- [DWARF JSON Files](dwarf-json-files.md) - Generating and managing DWARF files
- [radostrace](radostrace.md) - Radostrace documentation
- [osdtrace](osdtrace.md) - Osdtrace documentation
