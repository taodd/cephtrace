# Tracing Containerized Ceph Deployments

When Ceph runs in containers (cephadm, Rook/k8s, Docker, Podman), the cephtrace
binary runs on the host while the target process runs inside a container. The
procedure is the **same regardless of orchestrator** - cephtrace reads the
in-container binary through `/proc/<pid>/root`, so cephadm and Rook/k8s need no
different steps. What actually matters is only one thing: whether your
container's Ceph version has **embedded DWARF data**.

**Key points:**
- The binary runs on the host; the traced process runs in a container.
- DWARF data must match the *container's* Ceph version, not the host's.
- If the version is embedded (Part 1), there is nothing to download or
  configure. If it is not (Part 2), supply a matching DWARF file and skip the
  host version check.

---

## Part 1: Default - Embedded DWARF (no setup)

cephtrace ships with DWARF data for many common Ceph releases compiled into the
binary, matched by the ELF build-id of the binary *inside the container*. For
covered versions - including the CentOS Stream images used by cephadm and
Rook - tracing needs no DWARF download and no `--skip-version-check`.

### 1. Discover processes and check coverage

`--list` shows each process's host PID, container status, Ceph version, and a
`Traceable` column - `yes` means embedded DWARF data already covers this version.

```bash
# Clients (radosgw, qemu, ceph-mgr, ...)
sudo ./radostrace --list
#  PID        Container   Traceable   Ceph Version    Executable Path
#  ---------------------------------------------------------------------
#  12345      yes         yes         2:19.2.3-0.el9  /usr/bin/radosgw

# ceph-osd processes, with their OSD IDs
sudo ./osdtrace --list
#  PID        OSD ID     Container    Traceable   Ceph Version
#  -----------------------------------------------------------------------
#  23456      0          yes          yes         2:19.2.3-0.el9
#  23457      1          yes          yes         2:19.2.3-0.el9
```

Use `--list-embedded` to see every Ceph version with compiled-in DWARF data.

### 2. Trace directly

Use the host PID (and, for OSDs, the OSD ID) reported by `--list`:

```bash
# Client process - -p is mandatory for container-based tracing
sudo ./radostrace -p <HOST_PID>

# OSD - by OSD ID, by host PID, or every traceable OSD on the host
sudo ./osdtrace --id <OSD_ID>
sudo ./osdtrace -p <HOST_PID>
sudo ./osdtrace -a
```

If the `Traceable` column shows `yes`, you are done - skip Part 2 entirely.

---

## Part 2: Non-embedded versions (manual DWARF data)

When `--list` shows `Traceable = no` (your container's Ceph version isn't in
`--list-embedded`), supply DWARF data matching the *container's* Ceph version
and trace a specific PID with `--skip-version-check`.

### 1. Determine the container's Ceph version

```bash
# cephadm
cephadm shell -- ceph version
cephadm shell -- rpm -q ceph-osd        # RHEL / CentOS Stream
cephadm shell -- dpkg -l | grep ceph    # Ubuntu / Debian

# Rook/k8s - exec into the OSD/RGW pod and run the same commands
kubectl -n rook-ceph exec <pod> -- ceph version
```

### 2. Get a DWARF file matching that version

Pre-generated files live in the repo under `files/<distro>/<tool>/`, named by
the container's Ceph package version:

```bash
# CentOS Stream example (Ceph 19.2.3, el9)
wget https://raw.githubusercontent.com/taodd/cephtrace/main/files/centos-stream/radostrace/rados-2:19.2.3-0.el9_dwarf.json
wget https://raw.githubusercontent.com/taodd/cephtrace/main/files/centos-stream/osdtrace/osd-2:19.2.3-0.el9_dwarf.json

# Ubuntu example (Ceph 17.2.6, 22.04)
wget https://raw.githubusercontent.com/taodd/cephtrace/main/files/ubuntu/radostrace/17.2.6-0ubuntu0.22.04.2_dwarf.json
```

If no matching file exists, generate one (see [Generating DWARF data](#generating-dwarf-data) below).

### 3. Trace with --skip-version-check

```bash
# Client
sudo ./radostrace -i rados-2:19.2.3-0.el9_dwarf.json -p <HOST_PID> --skip-version-check

# OSD
sudo ./osdtrace -i osd-2:19.2.3-0.el9_dwarf.json -p <HOST_PID> --skip-version-check
```

**Why `--skip-version-check`?** The tool compares against the host's library
version, which differs from the container's. The check would otherwise fail
even though the DWARF file is correct for the container, so it must be skipped.

### Generating DWARF data

If no pre-generated DWARF file exists for your container's version:

#### Option A: generate inside the container

```bash
# Copy the cephtrace binary in, install debug symbols, export the JSON, copy it out
docker cp ./osdtrace <container>:/tmp/
docker exec <container> apt-get install -y ceph-osd-dbgsym   # use the matching debuginfo package for the distro
docker exec <container> /tmp/osdtrace -j /tmp/osd_dwarf.json
docker cp <container>:/tmp/osd_dwarf.json ./
```

For Rook/k8s, use `kubectl cp` and `kubectl exec` in place of `docker cp`/`docker exec`.

#### Option B: matching development environment

Set up a VM/host with the same OS and Ceph version as the container, install
debug symbols, and run `radostrace`/`osdtrace -j` to export the DWARF JSON. Copy
it to the production host and use it with `--skip-version-check`.

See [DWARF JSON Files](dwarf-json-files.md) for more on generating and managing DWARF data.

---

## kfstrace with Containers

**kfstrace works normally with containerized Ceph - no special steps.** It
traces the kernel module (`ceph.ko`), which runs on the host rather than inside
the container, so none of the above container complexity applies.

## See Also

- [Getting Started Guide](getting-started.md) - Basic installation
- [DWARF JSON Files](dwarf-json-files.md) - Generating and managing DWARF files
- [radostrace](radostrace.md) - Radostrace documentation
- [osdtrace](osdtrace.md) - Osdtrace documentation
