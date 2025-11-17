# Cephtrace
**eBPF-based dynamic tracing tools for Ceph - Zero downtime, minimal overhead**

Pinpoint performance bottlenecks with per-IO latency visibility across your entire Ceph stack. Currently three tools for real-time tracing (more coming):

- **[radostrace](doc/tools/radostrace.md)** - Trace librados based client operations
- **[osdtrace](doc/tools/osdtrace.md)** - Trace OSD operations with detailed latency breakdown
- **[kfstrace](doc/tools/kfstrace.md)** - Trace kernel client operations (CephFS/RBD)

**No service restarts. No configuration changes. Just run and trace.**

## Quick Start

See [Getting Started](doc/getting-started.md) for quick start instructions.

## Presentation

- [Efficient Ceph Performance Troubleshooting in Production Using eBPF][cephalocon2025] - Cephalocon 2025 (Video will be available soon)

## Documentation

### User Guides
- [radostrace](doc/tools/radostrace.md) - Client-side tracing
- [osdtrace](doc/tools/osdtrace.md) - OSD-side tracing
- [kfstrace](doc/tools/kfstrace.md) - Kernel client tracing
- [DWARF JSON Files](doc/dwarf-json-files.md) - Managing debug information

### Analysis
- [Radostrace Analysis](doc/analysis/analyze-radostrace.md) - Analyzing client traces
- [Osdtrace Analysis](doc/analysis/analyze-osdtrace.md) - Analyzing OSD traces

### Deployment
- [Containerized Ceph](doc/deployment/containerized-ceph.md) - Tracing containers (cephadm, Docker, Podman)

### Development
- [Building](doc/development/building.md) - Build from source

## Requirements

- Linux kernel 5.8+
- Ceph Octopus (15.x) - Squid (19.x)

## Contributing

- Report bugs: [GitHub Issues](https://github.com/taodd/cephtrace/issues)
- Submit DWARF files for new versions
- Submit pull requests

## License

GPL-2.0
