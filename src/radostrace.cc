//Main purpose for this client tracing
//1. observe the latency client -> osds for each read/write, if possible, including the network latency and the process latency
//   
#include <bpf/libbpf.h>
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <sys/resource.h>
#include <time.h>
#include <signal.h>
#include <bits/stdc++.h>

#include <cassert>
#include <cstring>
#include <ctime>
#include <iostream>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>

#include "radostrace.skel.h"

extern "C" {
#include <fcntl.h>
#include <unistd.h>
}

#include "bpf_osd_types.h"
#include "dwarf_parser.h"

#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))
using namespace std;

typedef std::map<std::string, int> func_id_t;

std::vector<std::string> probe_units = {"Objecter.cc"};

func_id_t func_id = {
      {"Objecter::_send_op", 0},
      {"Objecter::_finish_op", 10}
};


std::map<std::string, int> func_progid = {
      {"Objecter::_send_op", 0},
      {"Objecter::_finish_op", 1}

};


DwarfParser::probes_t rados_probes = {
      {"Objecter::_send_op",
       {{"op", "tid"},
        {"op", "target", "osd"}}},

      {"Objecter::_finish_op", 
       {{"op", "tid"},
	{"op", "target", "osd"}}}
};

void fill_map_hprobes(DwarfParser &dwarfparser, struct bpf_map *hprobes) {
  for (auto x : dwarfparser.func2vf) {
    std::string funcname = x.first;
    int key_idx = func_id[funcname];
    for (auto vf : x.second) {
      struct VarField_Kernel vfk;
      vfk.varloc = vf.varloc;
      clog << "fill_map_hprobes: "
           << "function " << funcname << " var location : register "
           << vfk.varloc.reg << " offset " << vfk.varloc.offset << " stack "
           << vfk.varloc.stack << endl;
      vfk.size = vf.fields.size();
      for (int i = 0; i < vfk.size; ++i) {
        vfk.fields[i] = vf.fields[i];
      }
      bpf_map__update_elem(hprobes, &key_idx, sizeof(key_idx), &vfk,
                           sizeof(vfk), 0);
      ++key_idx;
    }
  }
}

void signal_handler(int signum){
  clog << "Caught signal " << signum << endl;
  if (signum == SIGINT) {
      clog << "process killed" << endl;
  }
  exit(signum);
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
  if (level == LIBBPF_DEBUG) return 0;
  return vfprintf(stderr, format, args);
}

int attach_uprobe(struct radostrace_bpf *skel,
	           DwarfParser &dp,
	           std::string path,
		   std::string funcname,
		   int v = 0) {
  size_t func_addr = dp.func2pc[funcname];
  if (v > 0)
      funcname = funcname + "_v" + std::to_string(v); 
  int pid = func_progid[funcname];
  struct bpf_link *ulink = bpf_program__attach_uprobe(
      *skel->skeleton->progs[pid].prog, 
      false /* not uretprobe */,
      -1,
      path.c_str(), func_addr);
  if (!ulink) {
    cerr << "Failed to attach uprobe to " << funcname << endl;
    return -errno;
  }

  clog << "uprobe " << funcname <<  " attached" << endl;
  return 0;
}

int attach_retuprobe(struct radostrace_bpf *skel,
	           DwarfParser &dp,
	           std::string path,
		   std::string funcname,
		   int v = 0) {
  size_t func_addr = dp.func2pc[funcname];
  if (v > 0)
      funcname = funcname + "_v" + std::to_string(v); 
  int pid = func_progid[funcname];
  struct bpf_link *ulink = bpf_program__attach_uprobe(
      *skel->skeleton->progs[pid].prog, 
      true /* uretprobe */,
      -1,
      path.c_str(), func_addr);
  if (!ulink) {
    cerr << "Failed to attach uretprobe to " << funcname << endl;
    return -errno;
  }

  clog << "uretprobe " << funcname <<  " attached" << endl;
  return 0;
}

int main(int argc, char **argv) {
  signal(SIGINT, signal_handler); 

  //if (parse_args(argc, argv) < 0) return 0;

  struct radostrace_bpf *skel;
  // long uprobe_offset;
  int ret = 0;
  struct ring_buffer *rb;

  clog << "Start to parse dwarf info" << endl;

  std::string path = "/home/taodd/Git/ceph/build/lib/libceph-common.so";
  DwarfParser dwarfparser(path, rados_probes, probe_units);
  dwarfparser.parse();

  libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

  /* Set up libbpf errors and debug info callback */
  libbpf_set_print(libbpf_print_fn);

  /* Load and verify BPF application */
  clog << "Start to load uprobe" << endl;

  skel = radostrace_bpf__open_and_load();
  if (!skel) {
    cerr << "Failed to open and load BPF skeleton" << endl;
    return 1;
  }

  // map_fd = bpf_object__find_map_fd_by_name(skel->obj, "hprobes");

  fill_map_hprobes(dwarfparser, skel->maps.hprobes);

  clog << "BPF prog loaded" << endl;

  attach_uprobe(skel, dwarfparser, path, "Objecter::_send_op");
  attach_uprobe(skel, dwarfparser, path, "Objecter::_finish_op");
  sleep(60);
  return 0;
  /*
  clog << "New a ring buffer" << endl;

  rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
  if (!rb) {
    cerr << "failed to setup ring_buffer" << endl;
    goto cleanup;
  }

  clog << "Started to poll from ring buffer" << endl;

  clock_gettime(CLOCK_BOOTTIME, &lasttime);
  memset(op_stat, 0, MAX_OSD * sizeof(op_stat[0]));

  while ((ret = ring_buffer__poll(rb, 1000)) >= 0) {
  }*/

  /* we can also attach uprobe/uretprobe to any existing or future
   * processes that use the same binary executable; to do that we need
   * to specify -1 as PID, as we do here
   */
  /* Let libbpf perform auto-attach for uprobe_sub/uretprobe_sub
   * NOTICE: we provide path and symbol info in SEC for BPF programs
   */
  /*clog << "Unexpected line hit" << endl;
cleanup:
  clog << "Clean up the eBPF program" << endl;
  ring_buffer__free(rb);
  osdtrace_bpf__destroy(skel);
  return -errno;
  */
}

