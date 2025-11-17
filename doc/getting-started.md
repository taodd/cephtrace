# Getting Started with Cephtrace

This guide will help you install and start using cephtrace tools to trace your Ceph cluster operations.

## Quick Start for Ubuntu

The fastest way to start tracing on Ubuntu is using pre-built binaries and DWARF data files - no compilation or debug symbol installation required!

### Prerequisites

- Ubuntu 20.04, 22.04, or 24.04
- Kernel version 5.8 or higher
- Sudo/root access
- A running Ceph cluster

### Quick Start: radostrace

Run on machines with Ceph clients (VMs with RBD volumes, OpenStack services, RGW gateways):

```bash
# Download the binary
wget https://github.com/taodd/cephtrace/releases/latest/download/radostrace
chmod +x radostrace

# Check your Ceph version
dpkg -l | grep librados

# Download corresponding DWARF file (example for 17.2.6-0ubuntu0.22.04.2)
wget https://raw.githubusercontent.com/taodd/cephtrace/main/files/ubuntu/radostrace/17.2.6-0ubuntu0.22.04.2_dwarf.json

# Start tracing
sudo ./radostrace -i 17.2.6-0ubuntu0.22.04.2_dwarf.json
```

### Quick Start: osdtrace

Run on Ceph OSD nodes:

```bash
# Download the binary
wget https://github.com/taodd/cephtrace/releases/latest/download/osdtrace
chmod +x osdtrace

# Check your ceph-osd version
dpkg -l | grep ceph-osd

# Download corresponding DWARF file
wget https://raw.githubusercontent.com/taodd/cephtrace/main/files/ubuntu/osdtrace/17.2.6-0ubuntu0.22.04.2_dwarf.json

# Start tracing
sudo ./osdtrace -i 17.2.6-0ubuntu0.22.04.2_dwarf.json -x
```

### Quick Start: kfstrace

Run on machines using CephFS or kernel RBD clients. **No DWARF files needed!**

```bash
# Download the binary
wget https://github.com/taodd/cephtrace/releases/latest/download/kfstrace
chmod +x kfstrace

# Trace MDS requests (default)
sudo ./kfstrace

# Trace OSD requests
sudo ./kfstrace -m osd

# Trace both OSD and MDS requests
sudo ./kfstrace -m all
```

> See [DWARF JSON Files](dwarf-json-files.md) for more information about available DWARF files and version compatibility.

---

## Building from Source

For non-Ubuntu systems or if you want to build from source:

### 1. Clone the Repository

```bash
git clone https://github.com/taodd/cephtrace
cd cephtrace
git submodule update --init --recursive
```

### 2. Install Build Dependencies

#### Debian/Ubuntu

```bash
sudo apt-get install g++ clang libelf-dev libc6-dev libc6-dev-i386 libdw-dev
```

#### RHEL/CentOS/Rocky Linux

```bash
sudo dnf config-manager --enable crb
sudo dnf install g++ clang elfutils-libelf-devel glibc-devel glibc-devel.i686 elfutils-devel
```

#### Other Systems

For systems with different package managers, you'll need equivalent packages:
- C++ compiler (g++)
- Clang compiler (for eBPF)
- libelf development files
- libc development files (including 32-bit)
- libdw development files

### 3. Build the Tools

```bash
cd cephtrace
make
```

This will build all three tools: `radostrace`, `osdtrace`, and `kfstrace`.

## Debug Symbols (Alternative to DWARF Files)

If you don't have pre-generated DWARF JSON files for your Ceph version, you can install debug symbols on the machine where you'll run the tools.

### Ubuntu Debug Symbols

#### For radostrace:
```bash
sudo apt-get install librbd1-dbgsym librados2-dbgsym
```

#### For osdtrace:
```bash
sudo apt-get install ceph-osd-dbgsym
```

#### For kfstrace:
**No debug symbols required** - kfstrace uses kernel probes and doesn't need DWARF information.

> For more information on installing debug symbols on Ubuntu, see [Getting dbgsym Packages](https://ubuntu.com/server/docs/debug-symbol-packages#getting-dbgsymddeb-packages).

---

## System Requirements

### Minimum Kernel Version

- **Linux kernel 5.8 or higher** is required for all cephtrace tools

### Supported Architectures

- x86_64 (AMD64)
- Currently focused on x86_64; other architectures may require modifications

### Ceph Versions

Cephtrace has been tested with:
- Ceph Octopus (15.x)
- Ceph Pacific (16.x)
- Ceph Quincy (17.x)
- Ceph Reef (18.x)
- Ceph Squid (19.x)

> While newer Ceph versions should work, you may need to generate DWARF JSON files for your specific version. See [DWARF JSON Files](dwarf-json-files.md) for details.

---

## Next Steps

- **Learn about each tool:** [radostrace](tools/radostrace.md) | [osdtrace](tools/osdtrace.md) | [kfstrace](tools/kfstrace.md)
- **DWARF JSON files:** [Generation and usage guide](dwarf-json-files.md)
- **Deployment scenarios:** [Containerized Ceph](deployment/containerized-ceph.md) | [Production best practices](deployment/production-best-practices.md)
- **Development:** [Building](development/building.md) | [Architecture](development/architecture.md) | [Contributing](development/contributing.md)
