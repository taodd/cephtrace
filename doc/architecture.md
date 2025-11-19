# Cephtrace Architecture

This document provides an overview of how cephtrace tools work internally, their architecture, and key implementation details.

## Overview

Cephtrace tools use **eBPF (extended Berkeley Packet Filter)** technology to trace Ceph operations with minimal overhead. Each tool consists of two main components:

1. **eBPF program** (kernel space) - Attached to specific functions via uprobes/kprobes
2. **Userspace program** (C++) - Loads eBPF, manages data collection, formats output

## Technology Stack

### Core Technologies

- **eBPF:** Kernel tracing framework
  - Uprobes: Userspace function tracing (radostrace, osdtrace)
  - Kprobes: Kernel function tracing (kfstrace)
- **libbpf:** Library for loading and interacting with eBPF programs
- **DWARF:** Debug information format for structure parsing

### Dependencies

```
cephtrace/
├── libbpf/          (submodule) - BPF library
├── bpftool/         (submodule) - BPF code generation tool
└── external/json/   (submodule) - JSON library for DWARF export
```

## Tool Architecture

### Common Architecture Pattern

Each tool follows this pattern:

```
1. Parse DWARF information
   ├─ Read debug symbols from installed packages
   ├─ Or import from pre-generated JSON file
   └─ Extract struct layouts and function addresses

2. Load and attach eBPF program
   ├─ Compile BPF skeleton from .bpf.c
   ├─ Attach uprobes/kprobes to target functions
   └─ Set up BPF maps for data exchange

3. Event loop
   ├─ Read events from BPF ring buffer
   ├─ Parse event data (timestamps, latencies, metadata)
   └─ Format and print output

4. Cleanup
   ├─ Detach probes
   └─ Destroy BPF objects
```

## References

- [eBPF Documentation](https://ebpf.io/)
- [libbpf Documentation](https://libbpf.readthedocs.io/)
- [BPF CO-RE](https://nakryiko.com/posts/bpf-portability-and-co-re/)
- [DWARF Standard](http://dwarfstd.org/)
