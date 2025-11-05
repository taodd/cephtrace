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

| **kfstrace** [-t <seconds>] [-m <osd|mds|all>] -h


DESCRIPTION
===========

**kfstrace** Traces Ceph kernel client requests using kprobes, for ceph-fs
and kernel mounted rbd volumes.
installed ``cephtrace``.


OPTIONS
=======

-t, --timeout

   Set execution timeout in seconds

-m, --mode <osd|mds|all>

   Operation mode osd, mds or all

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
