<div align="center">

# 🔍 Cephtrace

### eBPF-Powered Performance Tracing for Ceph

**Zero downtime · Minimal overhead · Production-ready**

[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](https://www.gnu.org/licenses/gpl-2.0)
[![Build Status](https://github.com/taodd/cephtrace/workflows/build/badge.svg)](https://github.com/taodd/cephtrace/actions)

[Quick Start](#-quick-start) • [Documentation](#-documentation) • [Demo](#-demo) • [Contributing](#-contributing)

</div>

---

## 🎯 What is Cephtrace?

Cephtrace is a suite of **eBPF-based dynamic tracing tools** that provide **microsecond-level visibility** into your Ceph storage cluster's performance. Identify bottlenecks, diagnose slow operations, and understand exactly where latency occurs - all without restarting services or modifying configurations.

### ✨ Key Features

- **📊 Per-IO Latency Breakdown** - See exactly where each operation spends its time
- **🔄 No Downtime Required** - Attach and detach from running processes dynamically
- **⚙️  No Configuration Needed** - Just start tracing on the fly, no service restarts or config changes
- **📦 Works with Containers** - Full support for cephadm, Rook, Docker, lxd and MicroCeph
- **🚀 Low Overhead in Production** - eBPF with the kernel uprobe dynamic instrumentation

## 🛠️ The Tools

### 🔹 [osdtrace](doc/osdtrace.md) - OSD Performance Deep Dive

Trace OSD operations with detailed latency breakdown across:
- **Messenger layer:** Network throttling, receive, dispatch
- **OSD processing:** Queue wait, request handling, replication coordination
- **BlueStore backend:** Transaction prep, I/O wait, commit latencies

**Perfect for:**
- Diagnosing "slow ops" warnings
- Understanding replication latency
- Identifying storage vs network bottlenecks
- Inspecting BlueStore low-level metrics

### 🔹 [radostrace](doc/radostrace.md) - Client-Side Operation Tracking

Monitor librados client operations in real-time:
- Track read/write/delete/omap-related operations
- Measure end-to-end latency from client perspective
- Identify slow requests before they timeout
- Debug VM/application-level performance issues

**Perfect for:**
- VM/Application performance troubleshooting
- Precisely identify underperformed OSDs in large scaled cluster

### 🔹 [kfstrace](doc/kfstrace.md) - Kernel Client Tracing

Trace kernel-level CephFS and RBD operations:
- Monitor CephFS file operations
- Track RBD block I/O requests
- Measure kernel client latencies
- Debug mount and I/O issues

**Perfect for:**
- CephFS performance analysis
- Kernel RBD volume latency debugging
- Kernel client troubleshooting

## 🚀 Quick Start

**Example: Trace a VM's Ceph Operations from the Host**

Get up and running in under 2 minutes - monitor VM I/O operations hitting your Ceph cluster:

```bash
# Download radostrace
wget https://github.com/taodd/cephtrace/releases/latest/download/radostrace
chmod +x radostrace

# Check your librados version on the host
dpkg -l | grep librados2

# Download matching DWARF file (example for Ubuntu 22.04, Ceph 17.2.6)
wget https://raw.githubusercontent.com/taodd/cephtrace/main/files/ubuntu/radostrace/17.2.6-0ubuntu0.22.04.2_dwarf.json

# Find the QEMU process for your VM
ps aux | grep qemu

# Start tracing the VM's RBD operations (replace <qemu-pid> with actual PID)
sudo ./radostrace -i 17.2.6-0ubuntu0.22.04.2_dwarf.json -p <qemu-pid>

# Or trace all VMs on the host
sudo ./radostrace -i 17.2.6-0ubuntu0.22.04.2_dwarf.json
```

### Sampl Output:

```
     pid  client     tid  pool  pg     acting       w/r    size  latency     object[ops][offset,length]
   19015   34206  419357     2  1e     [1,11,121]     W        0     887     rbd_header.374de3730ad0[watch ]
   19015   34206  419358     2  1e     [1,11,121]     W        0    8561     rbd_header.374de3730ad0[call ]
   19015   34206  419359     2  39     [0,121,11]     R     4096    1240     rbd_data.374de3730ad0.0000000000000000[read ][0, 4096]
   19015   34206  419360     2  39     [0,121,11]     R     4096    1705     rbd_data.374de3730ad0.0000000000000000[read ][4096, 4096]
   19015   34206  419361     2  39     [0,121,11]     R     4096    1334     rbd_data.374de3730ad0.0000000000000000[read ][12288, 4096]
   19015   34206  419362     2  2b     [77,11,1]     iR     4096    2180     rbd_data.374de3730ad0.00000000000000ff[read ][4128768, 4096]
```

📖 **Detailed guide:** [Getting Started](doc/getting-started.md)

## 🎬 Demo

**📺 [10-Minute Live Demo](https://drive.google.com/file/d/12uwVptf_Gel7iN9Vkwo7JO3aClOASHH4/view?usp=drive_link)**(Demo is explained in below Cephalocon talk)

See cephtrace in action troubleshooting real performance issues.

**🎤 [Cephalocon 2025 Presentation](https://cephalocon2025.sched.com/event/27f3z/efficient-ceph-performance-troubleshooting-in-production-using-ebpf-dongdong-tao-canonical)**

"Efficient Ceph Performance Troubleshooting in Production Using eBPF" - Learn the techniques and real-world use cases.

## 📚 Documentation

### 📘 User Guides
| Tool | Description | Link |
|------|-------------|------|
| **osdtrace** | OSD-side tracing with detailed latency breakdown | [Guide](doc/osdtrace.md) |
| **radostrace** | Client-side librados operation tracing | [Guide](doc/radostrace.md) |
| **kfstrace** | Kernel client (CephFS/RBD) tracing | [Guide](doc/kfstrace.md) |
| **DWARF Files** | Managing debug information for tracing | [Guide](doc/dwarf-json-files.md) |

### 📊 Analysis & Tools
- **[Analyzing Radostrace Logs](doc/analyze-radostrace.md)** - Extract insights from client traces
- **[Analyzing Osdtrace Logs](doc/analyze-osdtrace.md)** - Deep-dive into OSD performance data

### 🐳 Deployment Scenarios
- **[Tracing Containerized Ceph](doc/tracing-containerized-ceph.md)** - cephadm, Rook, Docker, LXD
- **[Tracing MicroCeph](doc/tracing-microceph-snap.md)** - Snap-based deployments

### 🔨 Building
- **[Building from Source](doc/building.md)** - Compilation and installation guide

## Requirements
- **Kernel:** Linux 5.8 or later
- **Architecture:** x86_64

## 🤝 Contributing

We welcome contributions! Here's how you can help:

### 🐛 Report Issues
Found a bug or have a feature request?
- [Open an issue](https://github.com/taodd/cephtrace/issues)
- Provide Ceph version, OS, and reproduction steps

### 📝 Submit DWARF Files
Help expand version support:
1. Generate DWARF JSON for your Ceph version
2. Submit a PR to `files/` directory
3. Help others with the same version


## 📄 License

This project is licensed under the **GNU General Public License v2.0** - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built with [libbpf](https://github.com/libbpf/libbpf) and [bpftool](https://github.com/libbpf/bpftool)
- Inspired by the [bpftrace](https://github.com/iovisor/bpftrace), [SystemTap](https://sourceware.org/systemtap/), and [elfutils](https://sourceware.org/elfutils/) projects
---

<div align="center">

**Made with ❤️ for the Ceph community**

[⬆ Back to Top](#-cephtrace)

</div>
