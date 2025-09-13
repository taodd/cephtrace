# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Build System
- `make` - Build all binaries (radostrace and osdtrace)
- `make clean` - Clean build artifacts
- `make V=1` - Verbose build output

### Prerequisites
Install required packages on Debian/Ubuntu:
```bash
sudo apt-get install g++ clang libelf-dev libc6-dev-i386 libdw-dev
sudo apt-get install libdebuginfod-dev
```

Debug symbols are required for functionality:
- For radostrace: `sudo apt-get install librbd1-dbgsym librados2-dbgsym`  
- For osdtrace: `sudo apt-get install ceph-osd-dbgsym`

### Running Tools
All tools require root privileges and kernel v5.8+:
- `sudo ./radostrace` - Trace librados-based clients
- `sudo ./osdtrace -x` - Trace OSD operations
- `sudo ./kerneltrace` - Trace kernel Ceph client requests

JSON export/import workflow:
- Export DWARF: `sudo ./radostrace -j file.json`
- Import DWARF: `sudo ./radostrace -i file.json`

## Architecture

### High-Level Structure
Cephtrace is an eBPF-based dynamic tracing toolkit for Ceph components consisting of:

1. **Core Components**:
   - `radostrace` - Traces librados-based clients (RBD, RGW, etc.)
   - `osdtrace` - Traces Ceph OSD internal operations
   - `kerneltrace` - Traces kernel-level Ceph client requests (NEW)
   - `dwarf_parser` - Shared DWARF debug info parser

2. **Build Dependencies**:
   - Custom-built bpftool and libbpf (as git submodules)
   - nlohmann/json library for DWARF export/import
   - libdw/libelf for DWARF parsing

### Key Files and Directories
- `src/` - Main source code
  - `{tool}.cc` - Userspace tracing programs
  - `{tool}.bpf.c` - eBPF kernel programs  
  - `dwarf_parser.{cc,h}` - DWARF parsing shared code
  - `bpf_ceph_types.h` - Ceph-specific data structures
- `Makefile` - Build configuration with eBPF skeleton generation
- `bpftool/` - Git submodule for bpftool
- `libbpf/` - Git submodule for libbpf
- `external/json/` - nlohmann/json library

### Build Process
1. Builds libbpf as static library
2. Builds custom bpftool for skeleton generation
3. Compiles eBPF programs (.bpf.c) to bytecode
4. Generates C skeletons (.skel.h) from eBPF bytecode
5. Links userspace programs with eBPF skeletons

### DWARF Integration
The tools use DWARF debug information to:
- Locate function addresses for dynamic tracing
- Parse Ceph internal data structures at runtime
- Support multiple Ceph versions through JSON export/import

### Tracing Architecture
- **radostrace/osdtrace**: Use uprobes to hook Ceph library functions (requires DWARF)
- **kerneltrace**: Uses kprobes to hook kernel functions (no DWARF needed, uses BTF/CO-RE)
- eBPF maps store trace data and communicate with userspace
- Real-time output shows per-operation performance metrics
- Support for filtering by PID and timeouts

### kerneltrace Specifics
- **Target**: `net/ceph` kernel module functions (`send_request`, `handle_reply`)
- **Coverage**: All kernel Ceph clients (RBD, CephFS, etc.)
- **Data captured**: OSD acting sets, operation types, object names, latencies
- **Deployment**: No debug symbols required, easier production deployment