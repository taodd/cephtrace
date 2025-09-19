==========
radostrace
==========

------------------------------------
trace any librados based Ceph client
------------------------------------

:Version: @VERSION@
:Date: @DATE@
:Manual section: 8


SYNOPSIS
========

| **radostrace** [-t <seconds>] [-j [filename]] [-i <filename>] [-o [filename]] [-p <pid>]


DESCRIPTION
===========

**radostrace** radostrace can trace any librados based Ceph client, including
virtual machines using rbd backed volumes attached, rgw, cinder and glance.
installed ``cephtrace``.


OPTIONS
=======

-t, --timeout

   Set execution timeout in seconds

-j, --export-json <file>

   Export DWARF info to JSON (default: radostrace_dwarf.json)

-i, --import-json <file>

   Import DWARF info from JSON file

-o, --output <file>

   Export events data info to CSV (default: radostrace_events.csv)

-p, --pid <pid>

   Attach uprobes only to the specified process ID

-h, --help

   Show this help message


AVAILABILITY
============

**radostrace** is part of Cephtrace, a project that delivers various eBPF based ceph tracing tools.
These tools can be used to trace different Ceph components dynamically, without the need to restart
or reconfigure any of the Ceph related services. See https://github.com/taodd/cephtrace/ for more
information.


BUGS
====

Report issues at https://github.com/taodd/cephtrace/issues


SEE ALSO
========

osdtrace (8)
