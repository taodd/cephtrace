//Main purpose for this client tracing
//observe the client <-> osds latency for each request.

#include <bpf/libbpf.h>
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <sys/resource.h>
#include <time.h>
#include <signal.h>
#include <bits/stdc++.h>
#include <signal.h>
#include <unistd.h>

#include <cassert>
#include <cstring>
#include <ctime>
#include <iostream>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>
#include <fstream>
#include <dlfcn.h>
#include <link.h>

#include "radostrace.skel.h"

extern "C" {
#include <fcntl.h>
#include <unistd.h>
}

#include "bpf_ceph_types.h"
#include "dwarf_parser.h"

#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))
using namespace std;

typedef std::map<std::string, int> func_id_t;

std::vector<std::string> probe_units = {"Objecter.cc"};

func_id_t func_id = {
      {"Objecter::_send_op", 0},
      {"Objecter::_finish_op", 20}

};


std::map<std::string, int> func_progid = {
      {"Objecter::_send_op", 0},
      {"Objecter::_finish_op", 1}

};


DwarfParser::probes_t rados_probes = {
      {"Objecter::_send_op",
       {{"op", "tid"},
	{"this", "monc", "global_id"},
        {"op", "target", "osd"},
        {"op", "target", "base_oid", "name", "_M_string_length"},
        {"op", "target", "base_oid", "name", "_M_dataplus", "_M_p"},
        {"op", "target", "flags"},
        {"op", "target", "actual_pgid", "pgid", "m_pool"},
        {"op", "target", "actual_pgid", "pgid", "m_seed"},
        {"op", "target", "acting", "_M_impl", "_M_start"},
        {"op", "target", "acting", "_M_impl", "_M_finish"},
	{"op", "ops", "m_holder", "m_start"},
	{"op", "ops", "m_holder", "m_size"}}},
        //{"op", "ops", "m_holder", "m_start", "op", "op", "v"}}},
        //{"op", "ops", "m_holder", "m_start", "op", "extent", "offset", "v"},
        //{"op", "ops", "m_holder", "m_start", "op", "extent", "length", "v"}}},

      {"Objecter::_finish_op", 
       {{"op", "tid"},
	{"this", "monc", "global_id"},
	{"op", "target", "osd"}}}
};

volatile sig_atomic_t timeout_occurred = 0;

const char * ceph_osd_op_str(int opc) {
    const char *op_str = NULL;
#define GENERATE_CASE_ENTRY(op, opcode, str)	case CEPH_OSD_OP_##op: op_str=str; break;
    switch (opc) {
    __CEPH_FORALL_OSD_OPS(GENERATE_CASE_ENTRY)
    }
    return op_str;
}

void fill_map_hprobes(std::string mod_path, DwarfParser &dwarfparser, struct bpf_map *hprobes) {
  auto &func2vf = dwarfparser.mod_func2vf[mod_path];
  for (auto x : func2vf) {
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

void timeout_handler(int signum) {
    if (signum == SIGALRM) {
        timeout_occurred = 1;
    }
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

  auto &func2pc = dp.mod_func2pc[path];
  size_t func_addr = func2pc[funcname];
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
  auto &func2pc = dp.mod_func2pc[path];
  size_t func_addr = func2pc[funcname];
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

int digitnum(int x) {
  int cnt = 1;
  while(x / 10) {
    cnt++;
    x /= 10;
  }
  return cnt;
}

static int handle_event(void *ctx, void *data, size_t size) {
    struct client_op_v * op_v = (struct client_op_v *)data;
    std::stringstream ss;
    ss << std::hex << op_v->m_seed;
    std::string pgid(ss.str()); 

    // Define field widths based on actual data
    struct FieldWidths {
        int pid = 8;
        int client = 8; 
        int tid = 8;
        int pool = 6;
        int pg = 4;
        int acting = 18;
        int wr = 3;
        int size = 7;
        int latency = 8;
    };
    
    static FieldWidths widths;
    static bool firsttime = true;
    
    if (firsttime) {
        // Calculate field widths based on actual data from first event
        widths.pid = MAX(8, (int)std::to_string(op_v->pid).length() + 1);
        widths.client = MAX(8, (int)std::to_string(op_v->cid).length() + 1);
        widths.tid = MAX(8, (int)std::to_string(op_v->tid).length() + 1);
        widths.pool = MAX(6, (int)std::to_string(op_v->m_pool).length() + 1);
        widths.pg = MAX(4, (int)pgid.length() + 1);
        
        // Calculate acting field width
        std::stringstream acting_calc;
        acting_calc << "     [";
        bool first_acting = true;
        for (int i = 0; i < 8; ++i) {
            if(op_v->acting[i] < 0) break;
            if (!first_acting) acting_calc << ",";
            acting_calc << op_v->acting[i];
            first_acting = false;
        }
        acting_calc << "]";
        widths.acting = MAX(15, (int)acting_calc.str().length() + 1);
        
        widths.wr = 4; // "W" or "R" + padding
        widths.size = MAX(9, (int)std::to_string(op_v->length).length() + 1);
        
        long long latency = (op_v->finish_stamp - op_v->sent_stamp) / 1000;
        widths.latency = MAX(9, (int)std::to_string(latency).length() + 1);
        
        // Print header using calculated widths
        printf("%*s%*s%*s%*s%*s%*s%*s%*s%*s%s\n", 
               widths.pid, "pid",
               widths.client, "client", 
               widths.tid, "tid",
               widths.pool, "pool", 
               widths.pg, "pg",
               widths.acting, "acting",
               widths.wr + 1, "w/r",
               widths.size, "size",
               widths.latency, "latency",
               "     object[ops]");
        
        firsttime = false;
    }

    // Format output using calculated widths
    printf("%*d%*lld%*lld%*lld%*s", 
           widths.pid, op_v->pid,
           widths.client, op_v->cid, 
           widths.tid, op_v->tid,
           widths.pool, op_v->m_pool, 
           widths.pg, pgid.c_str()); 

    // Handle acting field with dynamic spacing
    std::stringstream acting_ss;
    acting_ss << "     [";
    bool first = true;
    for (int i = 0; i < 8; ++i) {
        if(op_v->acting[i] < 0) break;
        if (!first) acting_ss << ",";
        acting_ss << op_v->acting[i];
        first = false;
    }
    acting_ss << "]";
    
    std::string acting_str = acting_ss.str();
    printf("%*s", widths.acting, acting_str.c_str());

    // Format remaining fields with calculated widths
    std::string wr_str = op_v->rw & CEPH_OSD_FLAG_WRITE ? "W" : "R";
    printf("%*s%*lld%*lld", 
           widths.wr, wr_str.c_str(),
           widths.size, op_v->length,
           widths.latency, (op_v->finish_stamp - op_v->sent_stamp) / 1000);

    // Object name and operations (no fixed width needed)
    printf("     %s ", op_v->object_name);

    printf("[");
    bool print_offset_length = false;
    for (int i = 0; i < op_v->ops_size; ++i) {
        if (ceph_osd_op_extent(op_v->ops[i])) {
            printf("%s ", ceph_osd_op_str(op_v->ops[i]));
            print_offset_length = true;
        } else if (ceph_osd_op_call(op_v->ops[i])) {
            printf("call(%s.%s) ", op_v->cls_ops[i].cls_name, op_v->cls_ops[i].method_name);
        } else {
            printf("%s ", ceph_osd_op_str(op_v->ops[i]));
        }
    }
    printf("]");
    if (print_offset_length) {
        printf("[%lld, %lld]\n", op_v->offset, op_v->length);
    } else {
        printf("\n");
    }
    return 0;
}

std::string find_library_path(const std::string& lib_name) {
    // First try to find the library using dlopen
    void* handle = dlopen(lib_name.c_str(), RTLD_LAZY | RTLD_NOLOAD);
    if (!handle) {
        // If not loaded, try to load it
        handle = dlopen(lib_name.c_str(), RTLD_LAZY);
    }
    
    if (handle) {
        // Get the path using dlinfo
        struct link_map* link_map;
        if (dlinfo(handle, RTLD_DI_LINKMAP, &link_map) == 0 && link_map) {
            std::string path = link_map->l_name;
            dlclose(handle);
            if (!path.empty() && path != lib_name) {
                clog << "Found library " << lib_name << " at: " << path << endl;
                return path;
            }
        }
        dlclose(handle);
    }
    
    // Fallback: search in common library directories
    std::vector<std::string> search_dirs = {
        "/lib",
        "/lib64", 
        "/usr/lib",
        "/usr/lib64",
        "/lib/x86_64-linux-gnu",
        "/usr/lib/x86_64-linux-gnu",
        "/usr/lib/x86_64-linux-gnu/ceph",
        "/usr/local/lib"
    };
    
    // Try different possible filenames for the library
    std::vector<std::string> possible_names;
    if (lib_name.find(".so") == std::string::npos) {
        // If no .so extension, try common patterns
        possible_names.push_back("lib" + lib_name + ".so");
        possible_names.push_back("lib" + lib_name + ".so.1");
        possible_names.push_back("lib" + lib_name + ".so.2");
    } else {
        possible_names.push_back(lib_name);
    }
    
    for (const auto& dir : search_dirs) {
        for (const auto& name : possible_names) {
            std::string full_path = dir + "/" + name;
            if (access(full_path.c_str(), F_OK) == 0) {
                clog << "Found library " << lib_name << " at: " << full_path << endl;
                return full_path;
            }
        }
    }
    
    return "";
}

int main(int argc, char **argv) {
  signal(SIGINT, signal_handler); 

  /* Default to unlimited execution time */
  int timeout = -1;
  bool export_json = false;
  bool import_json = false;
  std::string json_output_file = "radostrace_dwarf.json";
  std::string json_input_file;

  /* Parse arguments */
  for (int i = 1; i < argc; ++i) {
      std::string arg = argv[i];
      if ((arg == "-t" || arg == "--timeout") && i + 1 < argc) {
          try {
              timeout = std::stoi(argv[++i]);
              if (timeout <= 0) throw std::invalid_argument("Negative timeout");
          } catch (...) {
              std::cerr << "Invalid timeout value. Must be a positive integer.\n";
              return 1;
          }
      } else if (arg == "-j" || arg == "--json") {
          export_json = true;
          if (i + 1 < argc && argv[i + 1][0] != '-') {
              json_output_file = argv[++i];
          }
      } else if (arg == "-i" || arg == "--import-json") {
          import_json = true;
          if (i + 1 < argc) {
              json_input_file = argv[++i];
          } else {
              std::cerr << "Error: -J/--import-json requires a filename argument\n";
              return 1;
          }
      } else if (arg == "-h" || arg == "--help") {
          std::cout << "Usage: " << argv[0] << " [-t <timeout seconds>] [--timeout <timeout seconds>] [-j [filename]] [-J <filename>]\n";
          std::cout << "  -t, --timeout <seconds>    Set execution timeout in seconds\n";
          std::cout << "  -j, --export-json <file>      Export DWARF info to JSON (default: radostrace_dwarf.json)\n";
          std::cout << "  -i, --import-json <file>   Import DWARF info from JSON file\n";
          std::cout << "  -h, --help                 Show this help message\n";
          return 0;
      }
  }

  /* Set up timeout if provided */
  if (timeout > 0) {
      signal(SIGALRM, timeout_handler);
      alarm(timeout);
      std::cout << "Execution timeout set to " << timeout << " seconds.\n";
  } else {
      std::cout << "No execution timeout set (unlimited).\n";
  }

  struct radostrace_bpf *skel;
  // long uprobe_offset;
  int ret = 0;
  struct ring_buffer *rb;

  DwarfParser dwarfparser(rados_probes, probe_units);
  
  // Use the new function to find library paths dynamically
  std::string librbd_path = find_library_path("librbd.so.1");
  std::string librados_path = find_library_path("librados.so.2");
  std::string libceph_common_path = find_library_path("libceph-common.so.2");

  if(librbd_path.empty() || librados_path.empty() || libceph_common_path.empty()) {
    cerr << "Error: Could not find one or more required Ceph libraries:" << endl;
    if (librbd_path.empty()) cerr << "  - librbd.so.1 not found" << endl;
    if (librados_path.empty()) cerr << "  - librados.so.2 not found" << endl;
    if (libceph_common_path.empty()) cerr << "  - libceph-common.so.2 not found" << endl;
    return 1;
  } else {
    clog << "Libraries to be traced: " << librbd_path << ", " << librados_path << ", " << libceph_common_path << endl;
  }

  if (import_json) {
      clog << "Importing DWARF info from " << json_input_file << endl;
      if (!dwarfparser.import_from_json(json_input_file)) {
          cerr << "Failed to import DWARF info from " << json_input_file << endl;
          return 1;
      }
  } else {
      clog << "Start to parse dwarf info" << endl;
      dwarfparser.add_module(librbd_path);
      dwarfparser.add_module(librados_path);
      dwarfparser.add_module(libceph_common_path);
      dwarfparser.parse();

      // Export DWARF info to JSON if requested
      if (export_json) {
          clog << "Exporting DWARF info to " << json_output_file << endl;
          dwarfparser.export_to_json(json_output_file);
      }
  }

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

  //fill_map_hprobes(libceph_common_path, dwarfparser, skel->maps.hprobes);
  fill_map_hprobes(librados_path, dwarfparser, skel->maps.hprobes);

  clog << "BPF prog loaded" << endl;

  attach_uprobe(skel, dwarfparser, librados_path, "Objecter::_send_op");
  attach_uprobe(skel, dwarfparser, librbd_path, "Objecter::_send_op");
  //attach_uprobe(skel, dwarfparser, libceph_common_path, "Objecter::_send_op");
  attach_uprobe(skel, dwarfparser, librados_path, "Objecter::_finish_op");
  attach_uprobe(skel, dwarfparser, librbd_path, "Objecter::_finish_op");
  //attach_uprobe(skel, dwarfparser, libceph_common_path, "Objecter::_finish_op");

  clog << "New a ring buffer" << endl;

  rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
  if (!rb) {
    cerr << "failed to setup ring_buffer" << endl;
    goto cleanup;
  }

  clog << "Started to poll from ring buffer" << endl;

  while ((!timeout_occurred || timeout == -1) && (ret = ring_buffer__poll(rb, 1000)) >= 0) {
      // Continue polling while timeout hasn't occurred or if unlimited execution time
  }

  if (timeout_occurred) {
      cerr << "Timeout occurred. Exiting." << endl;
  }

cleanup:
  clog << "Clean up the eBPF program" << endl;
  ring_buffer__free(rb);
  radostrace_bpf__destroy(skel);
  return timeout_occurred ? -1 : -errno;
}

