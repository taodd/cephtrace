========
osdtrace
========

-------------------------------------
probe and trace OSD(s) on given nodes
-------------------------------------

:Version: @VERSION@
:Date: @DATE@
:Manual section: 8


SYNOPSIS
========

| **osdtrace** [-s] [-b] [-A] [-l <milliseconds>] [-t <seconds>] [-j <filename>] [-i <filename>] [-a] [-p <pid1,pid2,...>] [--id <osd-id1,osd-id2,...>] [--skip-version-check] [--list] [--list-embedded] [-V] [-h]


DESCRIPTION
===========

**osdtrace** probes and traces ceph-osd processes directly on a given node,
printing a per-operation latency breakdown across the messenger, OSD
processing, and BlueStore layers. DWARF data for many Ceph releases is
compiled into the binary (matched by the ceph-osd ELF build-id), so covered
versions - including containerized OSDs - can be traced without debug symbols
or DWARF JSON files.


OPTIONS
=======

-s

   Single OP probe mode: log PrimaryLogPG::log_op_stats only (lower overhead).
   The default mode is full tracing with the complete latency breakdown.

-b

   Bluestore probe mode: trace BlueStore::log_latency and log_latency_fn,
   printing one line per call as "bluestore <name> lat <us>". <name> is the
   operation label the OSD itself passes to the function (e.g.
   _txc_committed_kv, kv_commit, _do_read, _remove), so the labels stay
   correct across Ceph versions.

-A

   Allocator probe mode: trace every call into the BlueStore/BlueFS
   free-space allocator. Each line reports the allocator instance
   (block, bluefs-wal/db/slow), the requested size, alignment unit and
   hint, the bytes actually allocated, the returned physical extents
   (a split request is a direct fragmentation signal), the call
   latency, and the calling thread. Can be combined with -b.

-l <milliseconds>

   Set operation latency threshold to capture

-t <seconds>

   Set execution timeout in seconds

-j <filename>

   Export DWARF parsing data to a JSON file and exit

-i <file>

   Import JSON DWARF data from file

-a, --all

   Trace ALL traceable ceph-osd processes on the host (native and
   containerized)

-p <pid1,pid2,...>

   Probe using process IDs (comma-separated; mandatory for tracing
   containerized processes by PID)

--id <osd-id1,osd-id2,...>

   Probe by OSD ID (comma-separated; resolves to PIDs via automatic
   discovery)

--skip-version-check

   Skip the version check when importing DWARF JSON (needed when the host and
   container package versions differ)

--list

   List active ceph-osd processes on the host (PID, OSD ID, container status,
   traceability, Ceph version) and exit

--list-embedded

   List the Ceph versions with DWARF data compiled into this binary and exit

-V, --version

   Print version information and exit

-h, --help

   Show this help message


AVAILABILITY
============

**osdtrace** is part of Cephtrace, a project that delivers various eBPF based ceph tracing tools.
These tools can be used to trace different Ceph components dynamically, without the need to restart
or reconfigure any of the Ceph related services. See https://github.com/taodd/cephtrace/ for more
information.


BUGS
====

Report issues at https://github.com/taodd/cephtrace/issues


SEE ALSO
========

radostrace (8)
