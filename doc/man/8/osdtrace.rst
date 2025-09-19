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

| **osdtrace** [-t <seconds>] [-j [filename]] [-i <filename>] [-o [filename]] [-p <pid>]


DESCRIPTION
===========

**osdtrace** osdtrace can probe and trace OSD(s) directly on given nodes.
  installed ``cephtrace``.


OPTIONS
=======

-d <seconds>

   Set probe duration in seconds to calculate average latency

-m <avg|max>

   Set operation latency collection mode

-l <milliseconds>

   Set operation latency threshold to capture

-o <osd-id>

   Only probe a specific OSD

-x

   Set probe mode to Full OPs. See below for details

-b

   Set probe mode to Bluestore. See below for details

-t

   Set execution timeout in seconds

-j

   Export DWARF parsing data

-i <file>

   Import JSON DWARF data from file

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
