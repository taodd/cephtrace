# Cephtrace
**eBPF-based dynamic tracing tools for Ceph - Zero downtime, minimal overhead**

Pinpoint performance bottlenecks with per-IO latency visibility across your entire Ceph stack. Currently three tools for real-time tracing (more coming):

- **[radostrace](doc/radostrace.md)** - Trace librados based client operations
- **[osdtrace](doc/osdtrace.md)** - Trace OSD operations with detailed latency breakdown
- **[kfstrace](doc/kfstrace.md)** - Trace kernel client operations (CephFS/RBD)

**No service restarts. No configuration changes. Just run and trace.**

## Quick Start

See [Getting Started](doc/getting-started.md) for quick start instructions.

## Presentation

- [Efficient Ceph Performance Troubleshooting in Production Using eBPF](https://cephalocon2025.sched.com/event/27f3z/efficient-ceph-performance-troubleshooting-in-production-using-ebpf-dongdong-tao-canonical) - Cephalocon 2025 (Video will be available soon)
- [10 mins Demo](https://drive.google.com/file/d/12uwVptf_Gel7iN9Vkwo7JO3aClOASHH4/view?usp=drive_link) (The demo is explained in the Cephalocon2025 presentation)

## Documentation

### User Guides
- [radostrace](doc/radostrace.md) - Client-side tracing
- [osdtrace](doc/osdtrace.md) - OSD-side tracing
- [kfstrace](doc/kfstrace.md) - Kernel client tracing
- [DWARF JSON Files](doc/dwarf-json-files.md) - Managing debug information

### Analysis
- [Radostrace Analysis](doc/analyze-radostrace.md) - Analyzing radostrace logs
- [Osdtrace Analysis](doc/analyze-osdtrace.md) - Analyzing osdtrace logs

### Deployment
- [Tracing Containerized Ceph](doc/tracing-containerized-ceph.md) - Tracing containers (cephadm, Docker)
- [Tracing MicroCeph](doc/tracing-microceph-snap.md) - Tracing MicroCeph snap-based deployments

### Development
- [Building](doc/building.md) - Build from source

## Requirements

- Linux kernel 5.8+
- Ceph Octopus (15.x) - Squid (19.x)

## Contributing

- Report bugs: [GitHub Issues](https://github.com/taodd/cephtrace/issues)
- Submit DWARF files for new versions
- Submit pull requests

## License

GPL-2.0
