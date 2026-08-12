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
#include <dirent.h>
#include <ctype.h>

#include "radostrace.skel.h"

extern "C" {
#include <fcntl.h>
#include <unistd.h>
}

#include "bpf_ceph_types.h"
#include "dwarf_parser.h"
#include "version_utils.h"
#include "utils.h"

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

// CSV Output
bool export_csv = false;
std::string csv_output_file = "radostrace_events.csv";

const char * ceph_osd_op_str(int opc) {
    const char *op_str = NULL;
#define GENERATE_CASE_ENTRY(op, opcode, str)	case CEPH_OSD_OP_##op: op_str=str; break;
    switch (opc) {
    __CEPH_FORALL_OSD_OPS(GENERATE_CASE_ENTRY)
    }
    return op_str;
}

void fill_map_hprobes(std::string mod_path, DwarfParser &dwarfparser, struct bpf_map *hprobes) {
  std::string mod_basename = get_basename(mod_path);
  auto &func2vf = dwarfparser.mod_func2vf[mod_basename];
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
		   int process_id = -1,
		   int v = 0) {

  std::string pid_path = path;
  if (process_id != -1) {
    pid_path = "/proc/" + std::to_string(process_id) + "/root" + path;
  }

  std::string path_basename = get_basename(path);
  auto &func2pc = dp.mod_func2pc[path_basename];
  size_t func_addr = func2pc[funcname];
  if (func_addr == 0) {
    cerr << "Warning: func_addr is zero for " << funcname << " in " << path << ", skipping uprobe" << endl;
    return -1;
  }
  if (v > 0)
      funcname = funcname + "_v" + std::to_string(v);
  int prog_id = func_progid[funcname];
  struct bpf_link *ulink = bpf_program__attach_uprobe(
      *skel->skeleton->progs[prog_id].prog,
      false /* not uretprobe */,
      process_id,  // Use the specified process ID
      pid_path.c_str(), func_addr);
  if (!ulink) {
    cerr << "Failed to attach uprobe to " << funcname << endl;
    return -errno;
  }

  if (process_id > 0) {
    clog << "uprobe " << funcname << " attached to process " << process_id << endl;
  } else {
    clog << "uprobe " << funcname << " attached to all processes" << endl;
  }
  return 0;
}

int attach_retuprobe(struct radostrace_bpf *skel,
	           DwarfParser &dp,
	           std::string path,
		   std::string funcname,
		   int process_id = -1,
		   int v = 0) {

  std::string pid_path = path;
  if (process_id != -1) {
    pid_path = "/proc/" + std::to_string(process_id) + "/root" + path;
  }

  std::string path_basename = get_basename(path);
  auto &func2pc = dp.mod_func2pc[path_basename];
  size_t func_addr = func2pc[funcname];
  if (func_addr == 0) {
    cerr << "Warning: func_addr is zero for " << funcname << " in " << path << ", skipping uretprobe" << endl;
    return -1;
  }
  if (v > 0)
      funcname = funcname + "_v" + std::to_string(v);
  int prog_id = func_progid[funcname];
  struct bpf_link *ulink = bpf_program__attach_uprobe(
      *skel->skeleton->progs[prog_id].prog,
      true /* uretprobe */,
      process_id,  // Use the specified process ID
      pid_path.c_str(), func_addr);
  if (!ulink) {
    cerr << "Failed to attach uretprobe to " << funcname << endl;
    return -errno;
  }

  if (process_id > 0) {
    clog << "uretprobe " << funcname << " attached to process " << process_id << endl;
  } else {
    clog << "uretprobe " << funcname << " attached to all processes" << endl;
  }
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
    (void)ctx;
    (void)size;
    struct client_op_v * op_v = (struct client_op_v *)data;
    std::stringstream ss;
    ss << std::hex << op_v->m_seed;
    std::string pgid(ss.str());

    // Properly Escape CSV Characters
    auto csv_escape = [](const std::string& in) -> std::string {
        bool need_quotes = false;
        for (char c : in) {
            if (c == ',' || c == '"' || c == '\n' || c == '\r') {
                need_quotes = true;
                break;
            }
        }
        if (!need_quotes) return in;
        std::string out;
        out.reserve(in.size() + 2);
        out.push_back('"');
        for (char c : in) {
            if (c == '"') out.push_back('"');
            out.push_back(c);
        }
        out.push_back('"');
        return out;
    };

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
    
    // Compile acting OSD list
    std::stringstream acting_osd_list;
    acting_osd_list << "[";
    {
        bool first = true;
        for (int i = 0; i < MAX_ACTING; ++i) {
            if (op_v->acting[i] < 0) break;
            if (!first) acting_osd_list << ",";
            acting_osd_list << op_v->acting[i];
            first = false;
        }
        acting_osd_list << "]";
    }
    std::string acting_str = acting_osd_list.str();

    // Compile Ops list
    std::stringstream ops_list;
    bool print_offset_length = false;
    ops_list << "[";
    for (__u32 i = 0; i < op_v->ops_size; ++i) {
        if (i) ops_list << " ";
        if (ceph_osd_op_extent(op_v->ops[i])) {
            ops_list << ceph_osd_op_str(op_v->ops[i]);
            print_offset_length = true;
        } else if (ceph_osd_op_call(op_v->ops[i])) {
            ops_list << "call(" << op_v->cls_ops[i].cls_name
                   << "." << op_v->cls_ops[i].method_name << ")";
        } else {
            ops_list << ceph_osd_op_str(op_v->ops[i]);
        }
    }
    ops_list << "]";
    std::string ops_str = ops_list.str();

    long long latency_us = (op_v->finish_stamp - op_v->sent_stamp) / 1000;
    std::string wr_str = (op_v->rw & CEPH_OSD_FLAG_WRITE) ? "W" : "R";

    // CSV output
    if (export_csv) {
        static bool csv_headers_printed = false;
        static FILE* csv_fp = nullptr;

        // Open CSV file
        if (!csv_fp) {
            csv_fp = fopen(csv_output_file.c_str(), "w");
            if (!csv_fp) {
                perror("fopen for CSV output failure");
                export_csv = false; // disable CSV output on failure
            }
        }
        // Print CSV Headers
        if (csv_fp && !csv_headers_printed) {
            fprintf(csv_fp, "pid,client,tid,pool,pg,acting,WR,size,latency,object,ops,offset,length\n");
            csv_headers_printed = true;
        }

        std::string offset_field = print_offset_length ? std::to_string(op_v->offset) : "";
        std::string length_field = print_offset_length ? std::to_string(op_v->length) : "";

        if (csv_fp) {
            fprintf(csv_fp,
               "%d,%lld,%lld,%lld,%s,%s,%s,%lld,%lld,%s,%s,%s,%s\n",
                op_v->pid,
                (long long)op_v->cid,
                (long long)op_v->tid,
                (long long)op_v->m_pool,
                pgid.c_str(),
                csv_escape(acting_str).c_str(),
                wr_str.c_str(),
                (long long)op_v->length,
                (long long)latency_us,
                csv_escape(op_v->object_name).c_str(),
                csv_escape(ops_str).c_str(),
                csv_escape(offset_field).c_str(),
                csv_escape(length_field).c_str());

            fflush(csv_fp); // Flush file to disk
        }
    }

    // Standard output
    if (firsttime) {
        // Calculate field widths based on actual data from first event
        widths.pid = MAX(8, (int)std::to_string(op_v->pid).length() + 1);
        widths.client = MAX(8, (int)std::to_string(op_v->cid).length() + 1);
        widths.tid = MAX(8, (int)std::to_string(op_v->tid).length() + 1);
        widths.pool = MAX(6, (int)std::to_string(op_v->m_pool).length() + 1);
        widths.pg = MAX(4, (int)pgid.length() + 1);
        widths.acting = MAX(15, (int)acting_str.length() + 1);
        widths.wr = 4;
        widths.size = MAX(9, (int)std::to_string(op_v->length).length() + 1);
        widths.latency = MAX(9, (int)std::to_string(latency_us).length() + 1);
        
        // Print header using calculated widths
        printf("%*s%*s%*s%*s%*s %*s%*s%*s%*s%s\n",
               widths.pid, "pid",
               widths.client, "client",
               widths.tid, "tid",
               widths.pool, "pool",
               widths.pg, "pg",
               widths.acting, "acting",
               widths.wr, "WR",
               widths.size, "size",
               widths.latency, "latency",
               "     object[ops]");
        
        firsttime = false;
    }

    // Format output using calculated widths
    // Note: explicit space after pg ensures separation from acting column
    // even when acting_str exceeds its calculated width
    printf("%*d%*lld%*lld%*lld%*s %*s",
           widths.pid, op_v->pid,
           widths.client, op_v->cid,
           widths.tid, op_v->tid,
           widths.pool, op_v->m_pool,
           widths.pg, pgid.c_str(),
           widths.acting, acting_str.c_str());

    printf("%*s%*lld%*lld",
           widths.wr, wr_str.c_str(),
           widths.size, op_v->length,
           widths.latency, latency_us);

    // Object name and operations (no fixed width needed)
    printf("     %s ", op_v->object_name);
    printf("%s", ops_str.c_str());

    if (print_offset_length) {
        printf("[%lld, %lld]\n", op_v->offset, op_v->length);
    } else {
        printf("\n");
    }

    return 0;
}

// One row of `--list` output: a client process that has libceph-common loaded.
struct CephClientInfo {
  int pid;
  std::string exe_path;
  bool is_container = false;
  std::string traceable = "unknown";  // "yes" / "no" / "unknown"
  std::string version = "unknown";    // authoritative only when traceable=="yes"
};

static std::string get_mnt_ns(int pid) {
  char buf[256];
  std::string p = "/proc/" + std::to_string(pid) + "/ns/mnt";
  ssize_t n = readlink(p.c_str(), buf, sizeof(buf) - 1);
  return n > 0 ? std::string(buf, n) : "";
}

// Discover client processes that have libceph-common loaded (i.e. the processes
// radostrace can attach to) and annotate each with container status, embedded-
// DWARF traceability, and Ceph version.  Mirrors osdtrace's --list.
std::vector<CephClientInfo> discover_ceph_clients() {
  std::vector<CephClientInfo> results;
  DIR *proc_dir = opendir("/proc");
  if (!proc_dir) {
    std::cerr << "Error: Could not open /proc directory" << std::endl;
    return results;
  }
  std::string self_ns = get_mnt_ns(getpid());

  struct dirent *entry;
  while ((entry = readdir(proc_dir)) != NULL) {
    if (entry->d_type != DT_DIR || !isdigit(entry->d_name[0]))
      continue;
    int pid = atoi(entry->d_name);
    if (pid <= 0)
      continue;

    // A process is a client iff it has libceph-common loaded; grab its path.
    std::string lib_path;
    std::ifstream maps("/proc/" + std::string(entry->d_name) + "/maps");
    std::string line;
    while (std::getline(maps, line)) {
      size_t slash = line.find('/');
      if (slash != std::string::npos &&
          line.find("libceph-common.so.2", slash) != std::string::npos) {
        lib_path = line.substr(slash);
        break;
      }
    }
    if (lib_path.empty())
      continue;

    CephClientInfo info;
    info.pid = pid;
    info.exe_path = get_exe_path_for_pid(pid);
    std::string ns = get_mnt_ns(pid);
    info.is_container = !self_ns.empty() && !ns.empty() && self_ns != ns;

    // Read the build-id through /proc/<pid>/root so containerized clients
    // resolve to the in-container library the uprobe would attach to.
    std::string bid = get_elf_build_id(
        "/proc/" + std::to_string(pid) + "/root" + lib_path);
    std::string matched;
    if (bid.empty()) {
      info.traceable = "unknown";  // couldn't read the build-id (usually non-root)
    } else if (DwarfParser::is_embedded_traceable(
                   {{"libceph-common.so.2", bid}}, "radostrace", &matched)) {
      info.traceable = "yes";
      if (!matched.empty()) info.version = matched;
    } else {
      info.traceable = "no";
      // Best-effort host package lookup for a native (non-container) client.
      if (!info.is_container) {
        std::string pkg = get_package_version(lib_path);
        if (!pkg.empty() && pkg != "unknown") info.version = pkg;
      }
    }
    results.push_back(info);
  }
  closedir(proc_dir);

  std::sort(results.begin(), results.end(),
            [](const CephClientInfo &a, const CephClientInfo &b) {
              return a.pid < b.pid;
            });
  return results;
}


int timeout = -1;
bool export_json = false;
bool import_json = false;
bool skip_version_check = false;
bool list_clients_mode = false;
bool list_embedded_mode = false;
std::string json_output_file = "radostrace_dwarf.json";
std::string json_input_file;
int process_id = -1;  // Default to -1 (all processes)

int parse_args(int argc, char **argv) {
  static struct option long_options[] = {
    {"timeout",            required_argument, 0, 't'},
    {"export-json",        optional_argument, 0, 'j'},
    {"import-json",        required_argument, 0, 'i'},
    {"output",             optional_argument, 0, 'o'},
    {"pid",                required_argument, 0, 'p'},
    {"skip-version-check", no_argument,       0, 0},
    {"list",               no_argument,       0, 0},
    {"list-embedded",      no_argument,       0, 0},
    {"version",            no_argument,       0, 'V'},
    {"help",               no_argument,       0, 'h'},
    {0, 0, 0, 0}
  };

  int option_index = 0;
  int opt;
  while ((opt = getopt_long(argc, argv, ":t:j::i:o::p:Vh", long_options, &option_index)) != -1) {
    switch (opt) {
      case 0:
        if (strcmp(long_options[option_index].name, "skip-version-check") == 0) {
          skip_version_check = true;
        } else if (strcmp(long_options[option_index].name, "list") == 0) {
          list_clients_mode = true;
        } else if (strcmp(long_options[option_index].name, "list-embedded") == 0) {
          list_embedded_mode = true;
        }
        break;
      case 't':
        try {
          timeout = std::stoi(optarg);
          if (timeout <= 0) throw std::invalid_argument("Negative timeout");
        } catch (...) {
          std::cerr << "Invalid timeout value. Must be a positive integer.\n";
          return -1;
        }
        break;
      case 'j':
        export_json = true;
        if (optarg) {
          json_output_file = optarg;
        } else if (optind < argc && argv[optind][0] != '-') {
          json_output_file = argv[optind++];
        }
        break;
      case 'i':
        import_json = true;
        json_input_file = optarg;
        break;
      case 'o':
        export_csv = true;
        if (optarg) {
          csv_output_file = optarg;
        } else if (optind < argc && argv[optind][0] != '-') {
          csv_output_file = argv[optind++];
        }
        break;
      case 'p':
        try {
          process_id = std::stoi(optarg);
          if (process_id <= 0) throw std::invalid_argument("Invalid PID");
        } catch (...) {
          std::cerr << "Invalid process ID. Must be a positive integer.\n";
          return -1;
        }
        break;
      case 'V':
        print_tool_version("radostrace");
        exit(0);
      case 'h':
        std::cout << "Usage: " << argv[0] << " [-t <timeout seconds>] [-j [filename]] [-i <filename>] [-o [filename]] [-p <pid>] [--skip-version-check] [--list] [--list-embedded]\n";
        std::cout << "  -t, --timeout <seconds>    Set execution timeout in seconds\n";
        std::cout << "  -j, --export-json <file>   Export DWARF info to JSON (default: radostrace_dwarf.json)\n";
        std::cout << "  -i, --import-json <file>   Import DWARF info from JSON file\n";
        std::cout << "  -o, --output <file>        Export events data info to CSV (default: radostrace_events.csv)\n";
        std::cout << "  -p, --pid <pid>            Attach uprobes only to the specified process ID (Mandatory for container based process tracing)\n";
        std::cout << "  --skip-version-check       Skip version check when importing DWARF JSON (currently needed for containers)\n";
        std::cout << "  --list                     List client processes using libceph-common (PID, container, traceability, version), and exit\n";
        std::cout << "  --list-embedded            List the Ceph versions with DWARF data compiled into this binary, and exit\n";
        std::cout << "  -V, --version              Print version information and exit\n";
        std::cout << "  -h, --help                 Show this help message\n";
        exit(0);
      case ':':
        std::cerr << "Option -" << (char)optopt << " requires an argument\n";
        return -1;
      case '?':
      default:
        std::cerr << "Unknown option. Use -h or --help for usage.\n";
        return -1;
    }
  }
  return 0;
}


int main(int argc, char **argv) {
  signal(SIGINT, signal_handler); 

  if (parse_args(argc, argv) != 0) {
    return 1;
  }

  if (list_embedded_mode) {
    DwarfParser::list_embedded_versions("radostrace");
    return 0;
  }

  if (list_clients_mode) {
    if (geteuid() != 0) {
      std::cout << "Warning: not running as root; processes owned by other users may be missed,"
                << " and Traceable/Ceph Version may show as unknown." << std::endl << std::endl;
    }
    auto clients = discover_ceph_clients();
    if (clients.empty()) {
      std::cout << "No client processes using libceph-common detected on the host." << std::endl;
    } else {
      std::cout << "Detected " << clients.size() << " client process(es) using libceph-common:" << std::endl;
      printf("  %-10s %-11s %-11s %-24s %s\n", "PID", "Container", "Traceable", "Ceph Version", "Executable Path");
      printf("  --------------------------------------------------------------------------------\n");
      for (const auto &c : clients) {
        printf("  %-10d %-11s %-11s %-24s %s\n", c.pid,
               c.is_container ? "yes" : "no", c.traceable.c_str(),
               c.version.c_str(), c.exe_path.empty() ? "unknown" : c.exe_path.c_str());
      }
      std::cout << std::endl
                << "Traceable: 'yes' means this radostrace has matching embedded DWARF data;"
                << " 'no' means it doesn't (export a DWARF JSON with -j on a matching host and"
                << " use -i); 'unknown' means a build-id couldn't be read (re-run as root)." << std::endl;
    }
    return 0;
  }

  // Validate process_id if specified
  if (process_id != -1) {
    std::string proc_path = "/proc/" + std::to_string(process_id);
    if (access(proc_path.c_str(), F_OK) != 0) {
      std::cerr << "Error: Process ID " << process_id << " does not exist" << std::endl;
      return 1;
    }
  }

  struct radostrace_bpf *skel;
  // long uprobe_offset;
  int ret = 0;
  struct ring_buffer *rb;

  DwarfParser dwarfparser(rados_probes, probe_units);

  auto export_path = [](const char *name, const char *library, int pid) {
    const char *path = getenv(name);
    return path && *path ? std::string(path)
                         : find_library_path(library, pid);
  };
  std::string librbd_path =
      export_path("CEPHTRACE_EXPORT_LIBRBD", "librbd.so.1", process_id);
  std::string librados_path =
      export_path("CEPHTRACE_EXPORT_LIBRADOS", "librados.so.2", process_id);
  std::string libceph_common_path =
      export_path("CEPHTRACE_EXPORT_LIBCEPH_COMMON",
                  "libceph-common.so.2", process_id);

  if(librbd_path.empty() || librados_path.empty() || libceph_common_path.empty()) {
    cerr << "Error: Could not find one or more required Ceph libraries:" << endl;
    if (librbd_path.empty()) cerr << "  - librbd.so.1 not found" << endl;
    if (librados_path.empty()) cerr << "  - librados.so.2 not found" << endl;
    if (libceph_common_path.empty()) cerr << "  - libceph-common.so.2 not found" << endl;
    return 1;
  } else {
    clog << "Libraries to be traced: " << librbd_path << ", " << librados_path << ", " << libceph_common_path << endl;
  }

  // Same rationale as osdtrace: skip the deleted-library check when we are
  // exporting JSON, since the export path intentionally wants to parse the
  // newly-upgraded on-disk binaries.
  if (!export_json && check_library_deleted(process_id, "librados")) {
     cerr << "Error: librados library mismatch detected!" << endl;
     cerr << "The ceph package has been upgraded on disk, but one or more processes are still using the old version in memory." << endl;
     cerr << "Please restart the affected processes to pick up the new version." << endl;
     return 1;
   }

  // Set by the embedded path on success; used later by the squid-version
  // gate so it doesn't need a separate dpkg/rpm shell-out.
  bool used_embedded = false;
  std::string embedded_matched_version;

  if (import_json) {
      clog << "Importing DWARF info from " << json_input_file << endl;

      std::string version = "";

      if (skip_version_check) {
          clog << "Skipping version check as requested" << endl;
      } else {
          // Get version information from the primary library (librados) for comparison
          version = get_package_version(librados_path);
          if (version != "unknown") {
              clog << "Current package version: " << version << endl;
          } else {
              clog << "Could not determine current package version for librados2, exit" << endl;
              return 1;
          }
      }

      if (!dwarfparser.import_from_json(json_input_file, version)) {
          cerr << "Failed to import DWARF info from " << json_input_file << endl;
          return 1;
      }
  } else {
      // When -j is used to export JSON, force live parsing so the output reflects
      // the installed binary (not a re-dump of the embedded data the header came
      // from). Otherwise try embedded DWARF data first, keyed by the on-disk
      // ELF build-id of libceph-common.so.2.  That single build-id pins the
      // exact package build (all three libs ship from it), so the matcher
      // selects the right entry and loads whatever modules it carries.
      //
      // The library paths are reported as they appear inside the target's
      // mount namespace; for containerized rbd clients (podman / docker)
      // those paths don't exist on the host.  Read the build-id through
      // /proc/<pid>/root/ when a target PID is specified so the read sees
      // the same file the uprobe will attach to.
      auto bid_path = [](const std::string& p) -> std::string {
          if (process_id == -1) return p;
          return "/proc/" + std::to_string(process_id) + "/root" + p;
      };
      std::vector<std::pair<std::string, std::string>> rados_mods = {
          {get_basename(libceph_common_path),
              get_elf_build_id(bid_path(libceph_common_path))},
      };
      if (!export_json && dwarfparser.import_from_embedded(
              rados_mods, "radostrace", &embedded_matched_version)) {
          used_embedded = true;
          // Detailed match info already logged inside import_from_embedded.
      } else {
          clog << "Start to parse dwarf info" << endl;
          dwarfparser.add_module(librbd_path);
          dwarfparser.add_module(librados_path);
          dwarfparser.add_module(libceph_common_path);
          dwarfparser.parse();
      }

      // Export DWARF info to JSON if requested.  Live-parse path only (we
      // forced export_json off the embedded branch above), so resolve the
      // version string from the package manager — the squid gate's path.
      if (export_json) {
          clog << "Exporting DWARF info to " << json_output_file << endl;

          std::string version = get_package_version(librados_path);
          if (version != "unknown") {
              clog << "Detected package version: " << version << endl;
          } else {
              clog << "Could not determine package version for librados2, using 'unknown'" << endl;
          }

          dwarfparser.export_to_json(json_output_file, version);
          clog << "Dwarf parsing data exported to " << json_output_file << endl;
          return 0;
      }
  }

  libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

  /* Set up libbpf errors and debug info callback */
  libbpf_set_print(libbpf_print_fn);

  /* Load and verify BPF application */
  clog << "Start to load uprobe" << endl;

  /* Open BPF skeleton first (before loading) */
  skel = radostrace_bpf__open();
  if (!skel) {
    cerr << "Failed to open BPF skeleton" << endl;
    return 1;
  }

  /* Set BPF global variables (rodata) - must be done after open but before load.
   * These values match the original macro definitions and typical Ceph builds.
   * Values differ between Ceph versions due to struct layout changes.
   */

  // Determine Ceph version for the squid struct-offset gate, in priority order:
  //   1. The "version" field of the JSON we just imported (-i path).
  //   2. The matched embedded entry's version (build-id-keyed fast path).
  //   3. dpkg/rpm package metadata for the live-parsed binary (live-parse path).
  std::string ceph_version;
  if (import_json) {
    ceph_version = get_version_from_json(json_input_file);
    clog << "Using version from JSON file: " << ceph_version << endl;
  } else if (used_embedded && !embedded_matched_version.empty()) {
    ceph_version = embedded_matched_version;
    clog << "Using version from embedded match: " << ceph_version << endl;
  } else {
    ceph_version = get_package_version(librados_path);
    clog << "Using version from package: " << ceph_version << endl;
  }

  bool is_squid_or_above = is_ceph_version_squid_or_above(ceph_version);

  if (is_squid_or_above) {
    // Ceph squid (19.2.0) and above: smaller OSDOp struct
    skel->rodata->CEPH_OSD_OP_SIZE = 112;              // sizeof(OSDOp) for squid+
    skel->rodata->CEPH_OSD_OP_BUFFER_CARRIAGE_OFFSET = 56; // offset to _carriage from OSDOp start for squid+
    clog << "Using Ceph squid (19.2.0+) struct offsets" << endl;
  } else {
    // Ceph reef (18.x) and earlier
    skel->rodata->CEPH_OSD_OP_SIZE = 152;              // sizeof(OSDOp) for pre-squid
    skel->rodata->CEPH_OSD_OP_BUFFER_CARRIAGE_OFFSET = 96; // offset to _carriage from OSDOp start for pre-squid
    clog << "Using Ceph pre-squid struct offsets" << endl;
  }

  skel->rodata->CEPH_OSD_OP_EXTENT_OFFSET_OFFSET = 6;   // offsetof(ceph_osd_op, extent.offset)
  skel->rodata->CEPH_OSD_OP_EXTENT_LENGTH_OFFSET = 14;  // offsetof(ceph_osd_op, extent.length)
  skel->rodata->CEPH_OSD_OP_CLS_CLASS_OFFSET = 6;       // offsetof(ceph_osd_op, cls.class_len)
  skel->rodata->CEPH_OSD_OP_CLS_METHOD_OFFSET = 7;      // offsetof(ceph_osd_op, cls.method_len)
  skel->rodata->CEPH_OSD_OP_BUFFER_RAW_OFFSET = 8;      // offset to _raw in ptr_node
  skel->rodata->CEPH_OSD_OP_BUFFER_DATA_OFFSET = 32;    // offset to data in raw

  clog << "Ceph struct offsets set in BPF globals:" << endl;
  clog << "  CEPH_OSD_OP_SIZE: " << skel->rodata->CEPH_OSD_OP_SIZE << endl;
  clog << "  CEPH_OSD_OP_EXTENT_OFFSET_OFFSET: " << skel->rodata->CEPH_OSD_OP_EXTENT_OFFSET_OFFSET << endl;
  clog << "  CEPH_OSD_OP_EXTENT_LENGTH_OFFSET: " << skel->rodata->CEPH_OSD_OP_EXTENT_LENGTH_OFFSET << endl;
  clog << "  CEPH_OSD_OP_BUFFER_CARRIAGE_OFFSET: " << skel->rodata->CEPH_OSD_OP_BUFFER_CARRIAGE_OFFSET << endl;

  /* Now load the BPF program with the configured globals */
  ret = radostrace_bpf__load(skel);
  if (ret) {
    cerr << "Failed to load BPF skeleton: " << ret << endl;
    radostrace_bpf__destroy(skel);
    return 1;
  }

  // Populate the per-function hprobes map from whichever library carries
  // the DWARF info.  In squid the Objecter symbol is statically duplicated
  // across all three libraries (same source, same compiler -> identical
  // varloc/fields), so later writes are no-ops; in tentacle the data only
  // lives in libceph-common.so.2.  fill_map_hprobes is a no-op for any
  // path whose mod_func2vf entry is empty.
  std::vector<std::string> rados_lib_paths = {
      librados_path, librbd_path, libceph_common_path};
  for (const auto& p : rados_lib_paths) {
    fill_map_hprobes(p, dwarfparser, skel->maps.hprobes);
  }

  clog << "BPF prog loaded" << endl;

  // Attach uprobes for every (lib, func) where the lib actually contains
  // the symbol.  attach_uprobe already prints "func_addr is zero ...
  // skipping" and returns -1 for the absent ones.  Without iterating all
  // three libs, tentacle (Objecter only in libceph-common) would attach
  // nothing and silently produce zero trace rows.
  for (const auto& p : rados_lib_paths) {
    attach_uprobe(skel, dwarfparser, p, "Objecter::_send_op", process_id);
    attach_uprobe(skel, dwarfparser, p, "Objecter::_finish_op", process_id);
  }

  clog << "New a ring buffer" << endl;

  rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
  if (!rb) {
    cerr << "failed to setup ring_buffer" << endl;
    goto cleanup;
  }

  /* Set up timeout if provided - start counting after initialization is complete */
  if (timeout > 0) {
      signal(SIGALRM, timeout_handler);
      alarm(timeout);
      std::cout << "Execution timeout set to " << timeout << " seconds.\n";
  } else {
      std::cout << "No execution timeout set (unlimited).\n";
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

