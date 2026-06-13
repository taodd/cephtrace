# Visualizing trace output

`radostrace` and `osdtrace` stream one line per IO - thousands of rows in a
typical capture. `tools/cephtrace_report.py` turns a capture into a
**one-screen visual summary** that answers the three questions you usually have
at a glance: *is it slow, what's slow, and where is the time going.*

It has no flags to remember - point it at a log (or pipe one in) and it
auto-detects which tool produced it.

```bash
# osdtrace
sudo ./osdtrace --id 0 -t 30 > osd.log
./tools/cephtrace_report.py osd.log

# radostrace (also reads the CSV that `radostrace -o` writes)
sudo ./radostrace -p <pid> -t 30 | ./tools/cephtrace_report.py
```

## osdtrace example

Real output from a ~116k-op capture (a single OSD under a 4 KiB write+read
workload):

```
osdtrace summary - 115829 OSD ops
  op_r 86926   op_w 28903

where the time goes   (share of total latency, avg 4.1ms/op)
     messenger  ▏                                        0%
         queue  ███▋                                     9%
           osd  ▉                                        2%
     bluestore  ████████████████▌                        41%
     +kv_commit ██████████████▊                          37%  (rocksdb commit)

op latency distribution   p50 4.0ms   p95 9.5ms   p99 11.3ms   max 30.1ms
     <250us  ████████████                             11896
     <500us  ██████████▌                              10420
       <1ms  ███████████████▊                         15594
       <2ms  █████████████▋                           13440
       <4ms  ██████▊                                  6647
       <8ms  ████████████████████████████████████████ 39612
      <16ms  ██████████████████▍                      18164
      <32ms                                           56

slowest ops
     30.1ms  op_w     osd.0 pg 2.12 4.0K
     28.0ms  op_w     osd.0 pg 2.e 4.0K

  -> deeper: ./tools/analyze_osdtrace_output.py <log> [-i | -f kv_commit | -o <osd>]
```

The **where the time goes** block is the headline: it turns osdtrace's dense
per-stage numbers into an instant "your latency is RocksDB commit, not network
or queueing." Because the stages overlap (`op_lat` is not their sum), the
shares are of total latency and need not add up to 100% - the point is which
stage dominates.

When a capture spans **more than one OSD**, an extra **per-OSD p95 latency**
block is drawn (highest p95 first), so an outlier OSD stands out immediately -
the single-OSD capture above omits it.

## radostrace example

```
radostrace summary - 353 client ops
    reads      152  ██████████████████████████████▎          43%
    writes     201  ████████████████████████████████████████ 56%

latency distribution   p50 3.5ms   p95 15.6ms   p99 19.4ms   max 19.7ms
       <1ms  ███████████████▋                         36
       <8ms  ████████████████████████████████████████ 92
      <16ms  █████████████████████████████▋           68

OSDs in the acting set of the slowest 17 ops
    osd.0    ████████████████████████ 17

  -> deeper: ./tools/analyze_radostrace_output.py <log> <osd_tree> [threshold_us]
```

The **OSDs in the acting set of the slowest ops** block is a quick culprit
pointer; for the full iterative ranking mapped to physical hosts, use the
analyzer it points to.

## Relationship to the analyzers

This tool is the visual *glance*. It deliberately reuses the existing parsers
(`analyze_osdtrace_output.parse_line` and `analyze_radostrace_output`'s format
detection) rather than maintaining a second one. When you need the numbers,
not the shape, use the detailed analyzers:

- [Analyzing osdtrace logs](analyze-osdtrace.md) - fio-style percentile tables,
  per-stage contribution (`-i`), per-OSD / per-field filtering
- [Analyzing radostrace logs](analyze-radostrace.md) - iterative culprit-OSD
  ranking mapped to hosts via `ceph osd tree`

## Notes

- Pure Python 3 standard library - no dependencies to install.
- The bars use Unicode block characters; any modern terminal renders them.
  Section headings are bold only when writing to a terminal, so piping or
  redirecting to a file stays clean.
- Reads either the default space-separated output or the CSV produced by
  `radostrace -o`.
