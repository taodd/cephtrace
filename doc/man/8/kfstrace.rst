========
kfstrace
========

------------------------------------------------
Traces Ceph kernel client requests using kprobes
------------------------------------------------

:Version: @VERSION@
:Date: @DATE@
:Manual section: 8


SYNOPSIS
========

| **kfstrace** [-t <seconds>] [-m <osd|mds|all>] [-l <microseconds>] [-V] [-h]


DESCRIPTION
===========

**kfstrace** traces Ceph kernel client requests using kprobes, for CephFS
and kernel-mounted RBD volumes.


OPTIONS
=======

-t, --timeout <seconds>

   Set execution timeout in seconds

-m, --mode <osd|mds|all>

   Operation mode: osd, mds, or all (default: mds)

-l, --latency <microseconds>

   Only show operations with latency greater than or equal to threshold

-V, --version

   Print version information and exit

-h, --help

   Show this help message


AVAILABILITY
============

**kfstrace** is part of Cephtrace, a project that delivers various eBPF based ceph tracing tools.
These tools can be used to trace different Ceph components dynamically, without the need to restart
or reconfigure any of the Ceph related services. See https://github.com/taodd/cephtrace/ for more
information.


BUGS
====

Report issues at https://github.com/taodd/cephtrace/issues


SEE ALSO
========

osdtrace (8)
