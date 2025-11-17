# Cephtrace

**eBPF-based dynamic tracing tools for Ceph**

Currently we have three tools for real-time Ceph operation tracing without service restarts:

- **[radostrace](doc/tools/radostrace.md)** - Trace librados based client operations
- **[osdtrace](doc/tools/osdtrace.md)** - Trace OSD operations with latency breakdown
- **[kfstrace](doc/tools/kfstrace.md)** - Trace kernel client operations (CephFS/RBD)

## Quick Start

See [Getting Started](doc/getting-started.md) for installation instructions.

**Ubuntu quick start:**
```bash
# Download binary and DWARF file
wget https://github.com/taodd/cephtrace/releases/latest/download/radostrace
wget https://raw.githubusercontent.com/taodd/cephtrace/main/files/ubuntu/radostrace/17.2.6-0ubuntu0.22.04.2_dwarf.json
chmod +x radostrace

# Start tracing
sudo ./radostrace -i 17.2.6-0ubuntu0.22.04.2_dwarf.json
```

## Documentation

### User Guides
- [Getting Started](doc/getting-started.md) - Installation and quick start
- [DWARF JSON Files](doc/dwarf-json-files.md) - Managing debug information
- [radostrace](doc/tools/radostrace.md) - Client-side tracing
- [osdtrace](doc/tools/osdtrace.md) - OSD-side tracing
- [kfstrace](doc/tools/kfstrace.md) - Kernel client tracing

### Analysis
- [Radostrace Analysis](doc/analysis/analyze-radostrace.md) - Analyzing client traces
- [Osdtrace Analysis](doc/analysis/analyze-osdtrace.md) - Analyzing OSD traces

### Deployment
- [Containerized Ceph](doc/deployment/containerized-ceph.md) - Tracing containers (cephadm, Docker, Podman)

### Development
- [Building](doc/development/building.md) - Build from source

## Features

- Zero downtime tracing
- Minimal overhead (< 1-2% CPU)
- Pre-built binaries for Ubuntu
- No debug symbols needed on production (DWARF JSON files)
- Detailed latency breakdown (osdtrace)

## Requirements

- Linux kernel 5.8+
- Ceph Octopus (15.x) - Squid (19.x)

## Pre-generated DWARF Files

- Ubuntu: [files/ubuntu/](files/ubuntu/)
- CentOS Stream: [files/centos-stream/](files/centos-stream/)

Missing your version? See [DWARF JSON Files guide](doc/dwarf-json-files.md).

## Contributing

- Report bugs: [GitHub Issues](https://github.com/taodd/cephtrace/issues)
- Submit DWARF files for new versions
- Submit pull requests

## License

GPL-2.0
