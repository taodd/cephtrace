# DWARF JSON Files

DWARF JSON files allow you to use cephtrace tools without installing debug symbols on every target machine. This guide explains how to generate, use, and manage these files.

## What are DWARF Files?

DWARF is a debugging data format that contains information about:
- Data structure layouts (struct members, offsets, sizes)
- Type definitions
- Variable locations
- Function addresses

The cephtrace tools (radostrace and osdtrace) need this information to:
- Locate specific functions in the Ceph binaries for uprobe attachment
- Parse internal Ceph data structures

### Why Use JSON Export?

**Traditional approach (without JSON):**
- Install debug symbol packages on every target machine
- Each machine parses DWARF data at startup (~3-10 seconds overhead)
- Requires internet access or local debug package repositories
- Can consume significant disk space (100+ MB per package)

**JSON export approach:**
- Generate DWARF JSON once on a development/staging machine
- Copy small JSON file to target machines (typically 50-200 KB)
- No debug symbols needed on production machines
- Faster startup (no parsing overhead)
- Consistent results across machines

## Pre-generated DWARF Files

We provide pre-generated DWARF JSON files for common Ceph versions:

### Ubuntu

Location: `files/ubuntu/{radostrace,osdtrace}/`

Available versions include:
- Ubuntu 20.04: Ceph 15.2.17, 17.2.x series
- Ubuntu 22.04: Ceph 17.2.x, 19.2.x series
- Ubuntu 24.04: Ceph 19.2.x series

File naming format: `<version>_dwarf.json`
- Example: `17.2.6-0ubuntu0.22.04.2_dwarf.json`

### CentOS Stream

Location: `files/centos-stream/{radostrace,osdtrace}/`

Available versions:
- Ceph 18.2.7 (CentOS Stream 9)
- Ceph 19.2.3 (CentOS Stream 9)

File naming format: `{rados,osd}-<version>_dwarf.json`
- Example: `rados-2:19.2.3-0.el9_dwarf.json`
- Example: `osd-2:19.2.3-0.el9_dwarf.json`

> To check available DWARF files, browse the repository:
> - [Ubuntu radostrace files](https://github.com/taodd/cephtrace/tree/main/files/ubuntu/radostrace)
> - [Ubuntu osdtrace files](https://github.com/taodd/cephtrace/tree/main/files/ubuntu/osdtrace)
> - [CentOS Stream radostrace files](https://github.com/taodd/cephtrace/tree/main/files/centos-stream/radostrace)
> - [CentOS Stream osdtrace files](https://github.com/taodd/cephtrace/tree/main/files/centos-stream/osdtrace)

## Generating DWARF JSON Files

If you need a DWARF JSON file for a Ceph version that doesn't have a pre-generated file, you can create one yourself.

### Generating with GitHub Actions

The repository includes a GitHub Actions workflow that can generate Ubuntu DWARF JSON files across a configurable matrix of Ubuntu releases and Ceph versions.

Workflow: `.github/workflows/generate-dwarf-json.yaml`

Configuration file: `.github/dwarf-json-versions.json`

The configuration has two sections:

- `latest`: generate files for the latest Ceph package currently available from the Ubuntu repositories for each Ubuntu release.
- `manual`: generate files for Ceph versions listed in the config. Values like `18.2.7` use the official `https://download.ceph.com/debian-18.2.7/` repository. Full Ubuntu package versions like `17.2.6-0ubuntu0.22.04.3` use Ubuntu APT/Launchpad.

Example manual entry:

```json
{
  "name": "ubuntu-22.04-ceph-18.2.7",
  "ubuntu": "22.04",
  "version": "18.2.7"
}
```

If an exact Ubuntu package version is no longer installable through APT, add a `launchpad_files_url` value that points to the matching Launchpad build `+files` page:

```json
{
  "name": "ubuntu-22.04-ceph-17.2.6",
  "ubuntu": "22.04",
  "version": "17.2.6-0ubuntu0.22.04.3",
  "launchpad_files_url": "https://launchpad.net/ubuntu/+source/ceph/17.2.6-0ubuntu0.22.04.3/+build/.../+files"
}
```

To run it manually:

1. Open the `Generate DWARF JSON Files` workflow in GitHub Actions.
2. Select one of these modes:
   - `latest`: only the latest rows.
   - `manual`: only exact-version rows.
   - `all`: both latest and manual rows.
3. Download the `ubuntu-dwarf-json-files` artifact when the workflow completes.

The workflow generates files in the same layout used by the repository:

```text
files/ubuntu/osdtrace/osd-<version>_dwarf.json
files/ubuntu/radostrace/<version>_dwarf.json
```

If the expected file already exists in the repository checkout, the workflow does not overwrite it. If both the `osdtrace` and `radostrace` files for a matrix row already exist, the row skips package installation, build, and generation, then stages the existing files into the artifact.

The workflow is currently manual-only and runs from the GitHub Actions UI or pull request checks.

### Prerequisites

1. A machine with the target Ceph version installed
2. Debug symbols for the appropriate package:
   - For radostrace: `librbd1-dbgsym` and `librados2-dbgsym` (Ubuntu) or `librbd1-debuginfo` (RHEL)
   - For osdtrace: `ceph-osd-dbgsym` (Ubuntu) or `ceph-osd-debuginfo` (RHEL)
3. The cephtrace binary (radostrace or osdtrace)

### Generation Steps

#### For radostrace:

```bash
# Check your librados version
dpkg -l | grep librados   # Ubuntu
rpm -q librados2          # RHEL

# Install debug symbols (Ubuntu example)
sudo apt-get install librados2-dbgsym librbd1-dbgsym

# Generate DWARF JSON file
sudo ./radostrace -j radostrace_dwarf.json

# The file will be created with version information embedded
```

#### For osdtrace:

```bash
# Check your ceph-osd version
dpkg -l | grep ceph-osd   # Ubuntu
rpm -q ceph-osd           # RHEL

# Install debug symbols (Ubuntu example)
sudo apt-get install ceph-osd-dbgsym

# Generate DWARF JSON file
sudo ./osdtrace -j osdtrace_dwarf.json
```

### What's in the JSON File?

The generated JSON file contains:
- **Version information:** Package name and version string
- **Function addresses:** Locations of functions to probe
- **Struct layouts:** Member offsets and sizes for Ceph internal structures
- **Type information:** Data types and their properties

The version information is automatically embedded and used for compatibility checking when importing.

## Using DWARF JSON Files

### Import and Run

Use the `-i` flag to import a DWARF JSON file:

```bash
# radostrace with DWARF JSON
sudo ./radostrace -i radostrace_dwarf.json

# osdtrace with DWARF JSON
sudo ./osdtrace -i osdtrace_dwarf.json -x
```

### Version Compatibility Checking

The tools automatically verify version compatibility:

1. **On import:** The tool reads the version information from the JSON file
2. **On target:** The tool checks the version of the installed Ceph packages
3. **Comparison:** If versions don't match, the tool reports an error and exits

Example error:

```
Error: Version mismatch!
JSON file: librados2 17.2.6-0ubuntu0.22.04.2
Installed: librados2 17.2.7-0ubuntu0.22.04.1

Please generate a new DWARF JSON file for your Ceph version.
```

### Skipping Version Check

In some scenarios (e.g., containerized Ceph deployments), you may need to skip the version check:

```bash
sudo ./radostrace -i radostrace_dwarf.json --skip-version-check
```

**Use this flag when:**
- Tracing processes in containers from the host
- The dwarf json file to import should be the same version with the ceph package inside the container 

**Warning:** version mismatch between ceph package and dwarf json file can cause undefined results (often unable to output anything). Only skip version checking for containerized or snapped ceph tracing.

## File Organization

For managing multiple versions, we use this structure:

```
dwarf-files/
├── ubuntu/
│   ├── 22.04/
│   │   ├── radostrace/
│   │   │   ├── 17.2.6-0ubuntu0.22.04.2_dwarf.json
│   │   │   └── 17.2.7-0ubuntu0.22.04.1_dwarf.json
│   │   └── osdtrace/
│   │       ├── 17.2.6-0ubuntu0.22.04.2_dwarf.json
│   │       └── 17.2.7-0ubuntu0.22.04.1_dwarf.json
│   └── 24.04/
│       └── ...
└── centos-stream/
    └── 9/
        ├── radostrace/
        │   └── rados-2:19.2.3-0.el9_dwarf.json
        └── osdtrace/
            └── osd-2:19.2.3-0.el9_dwarf.json
```

## See Also

- [Getting Started Guide](getting-started.md) - Installation and basic usage
- [radostrace Documentation](tools/radostrace.md) - Detailed radostrace usage
- [osdtrace Documentation](tools/osdtrace.md) - Detailed osdtrace usage
- [Containerized Ceph](deployment/containerized-ceph.md) - Using DWARF files with containers
