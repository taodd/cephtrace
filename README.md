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

- [Efficient Ceph Performance Troubleshooting in Production Using eBPF](https://cephalocon2025.sched.com/event/27f3z/efficient-ceph-performance-troubleshooting-in-production-using-ebpf-dongdong-tao-canonical) - Cephalocon 2025 (Video will be available soon)
- [10 mins Demo](https://drive.google.com/file/d/12uwVptf_Gel7iN9Vkwo7JO3aClOASHH4/view?usp=drive_link) (The demo is explained in the Cephalocon2025 presentation)

## Documentation

### User Guides
- [radostrace](doc/tools/radostrace.md) - Client-side tracing
- [osdtrace](doc/tools/osdtrace.md) - OSD-side tracing
- [kfstrace](doc/tools/kfstrace.md) - Kernel client tracing
- [DWARF JSON Files](doc/dwarf-json-files.md) - Managing debug information

### Analysis
- [Radostrace Analysis](doc/analysis/analyze-radostrace.md) - Analyzing radostrace logs
- [Osdtrace Analysis](doc/analysis/analyze-osdtrace.md) - Analyzing osdtrace logs

### Deployment
- [Tracing Containerized Ceph](doc/deployment/tracing-containerized-ceph.md) - Tracing containers (cephadm, Docker)
- [Tracing MicroCeph](doc/deployment/tracing-microceph-snap.md) - Tracing MicroCeph snap-based deployments

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
