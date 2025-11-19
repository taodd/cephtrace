# Tracing MicroCeph Snap-based Deployments

MicroCeph deploys Ceph using snap packages, which provides a self-contained Ceph deployment. The tracing process is similar to containerized Ceph, with some snap-specific considerations.

## Overview

**Key Points:**
- Tracing process is similar to containerized Ceph deployments
- Binary runs on host, traced process runs inside snap namespace
- DWARF files must match the snap's Ceph version, not the host's
- **Critical:** Use snap manifest to determine exact Ceph package version

**Solutions:**
- Use `--skip-version-check` flag
- Specify exact process ID with `-p`
- Generate or download DWARF files matching snap's Ceph version

## Determining Snap's Ceph Version

The snap contains specific package versions that may differ from what's on your host.

### Check Snap Manifest

```bash
# View the snap manifest to see all package versions
cat /snap/microceph/current/snap/manifest.yaml

# Filter for specific Ceph library versions
cat /snap/microceph/current/snap/manifest.yaml | grep librados2

# Example output:
# librados2: 17.2.6-0ubuntu0.22.04.3

# You can also check other Ceph packages
cat /snap/microceph/current/snap/manifest.yaml | grep ceph-osd
```
The version string (e.g., `17.2.6-0ubuntu0.22.04.3`) is what you need for downloading or generating the correct DWARF files.

## Identifying process ID

### Find Client Processes (for radostrace)

Take radosgw for example:

```bash
# Find processes using radosgw
ps aux | grep radosgw
```

### Find OSD Processes (for osdtrace)

```bash
# Find ceph-osd processes on host
ps aux | grep ceph-osd
```

The PID shown is the host PID, which is what you'll use with osdtrace.

## Tracing MicroCeph

### radostrace for MicroCeph

```bash
# 1. Determine the exact librados version from snap manifest
cat /snap/microceph/current/snap/manifest.yaml | grep librados2
# Output: librados2: 17.2.6-0ubuntu0.22.04.3

# 2. Download radostrace binary
wget https://github.com/taodd/cephtrace/releases/latest/download/radostrace
chmod +x radostrace

# 3. Download DWARF file matching the snap's librados version
# Example for version 17.2.6-0ubuntu0.22.04.3
wget https://raw.githubusercontent.com/taodd/cephtrace/main/files/ubuntu/radostrace/17.2.6-0ubuntu0.22.04.3_dwarf.json

# 4. Find the client process PID on the host
ps aux | grep <your_client_process>

# 5. Trace with --skip-version-check
sudo ./radostrace -i 17.2.6-0ubuntu0.22.04.3_dwarf.json -p <HOST_PID> --skip-version-check
```

**Why skip version check?**
- The tool checks the host's library version
- Snap has different library version in its isolated environment
- Version check would fail even though DWARF file is correct for the snap

### osdtrace for MicroCeph

```bash
# 1. Determine the exact ceph-osd version from snap manifest
cat /snap/microceph/current/snap/manifest.yaml | grep ceph-osd
# Output: ceph-osd: 17.2.6-0ubuntu0.22.04.3

# 2. Download osdtrace binary
wget https://github.com/taodd/cephtrace/releases/latest/download/osdtrace
chmod +x osdtrace

# 3. Download DWARF file matching the snap's ceph-osd version
wget https://raw.githubusercontent.com/taodd/cephtrace/main/files/ubuntu/osdtrace/17.2.6-0ubuntu0.22.04.3_dwarf.json

# 4. Find the ceph-osd process PID on the host
ps aux | grep ceph-osd

# 5. Trace with --skip-version-check and extended output
sudo ./osdtrace -i 17.2.6-0ubuntu0.22.04.3_dwarf.json -p <HOST_PID> --skip-version-check -x
```

## Generating DWARF Files for MicroCeph

If pre-generated DWARF files aren't available for your snap's Ceph version:

### Method 1: Generate on Matching Ubuntu System

```bash
# Set up Ubuntu system matching your snap's base (e.g., Ubuntu 22.04)
# Install the exact Ceph version from snap manifest
sudo apt-get install ceph-osd=17.2.6-0ubuntu0.22.04.3
sudo apt-get install ceph-osd-dbgsym=17.2.6-0ubuntu0.22.04.3

# Download cephtrace
wget https://github.com/taodd/cephtrace/releases/latest/download/osdtrace
chmod +x osdtrace

# Generate DWARF file
sudo ./osdtrace -j osd_17.2.6-0ubuntu0.22.04.3_dwarf.json

# Copy DWARF file to your MicroCeph host
```

## kfstrace with MicroCeph

**Good news:** kfstrace works normally with MicroCeph!

**Why?** kfstrace traces the kernel module (`ceph.ko`), not the snap processes. The kernel module runs on the host, so there's no snap complexity.

```bash
# Download and run kfstrace normally
wget https://github.com/taodd/cephtrace/releases/latest/download/kfstrace
chmod +x kfstrace
sudo ./kfstrace
```

## See Also

- [Tracing Containerized Ceph](tracing-containerized-ceph.md) - Similar concepts for container deployments
- [DWARF JSON Files](dwarf-json-files.md) - Generating and managing DWARF files
