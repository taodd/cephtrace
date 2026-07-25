#include <bpf/libbpf.h>
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <sys/resource.h>
#include <csignal>
#include <set>
#include <algorithm>
#include <chrono>
#include <sstream>
#include <cstring>
#include <ctime>
#include <iostream>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>
#include <fstream>
#include <dirent.h>
#include <ctype.h>

#include "osdtrace.skel.h"

extern "C" {
#include <fcntl.h>
#include <unistd.h>
}

#include "bpf_ceph_types.h"
#include "dwarf_parser.h"
#include "version_utils.h"
#include "utils.h"

#define MAX_CNT 100000ll
#define MAX_OSD 4000
#define PATH_MAX 4096

#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))
using namespace std;

typedef std::map<std::string, int> func_id_t;

std::vector<std::string> probe_units = {
    "OpRequest.cc", "OSD.cc", "BlueStore.cc", "PrimaryLogPG.cc", "ReplicatedBackend.cc", "ECBackend.cc"};

func_id_t func_id = {
    {"OSD::enqueue_op", 0},
    {"OSD::dequeue_op", 10},
    {"PrimaryLogPG::execute_ctx", 20},
    {"ReplicatedBackend::submit_transaction", 30},
    {"BlueStore::queue_transactions", 40},
    {"BlueStore::_do_write", 50},
    {"BlueStore::_wctx_finish", 60},
    {"BlueStore::_txc_state_proc", 70},
    {"BlueStore::_txc_apply_kv", 80},
    {"PrimaryLogPG::log_op_stats", 90},
    {"ReplicatedBackend::generate_subop", 100},
    {"ReplicatedBackend::do_repop_reply", 110},
    {"OpRequest::mark_flag_point_string", 120},
    {"BlueStore::log_latency", 130},
    {"log_subop_stats", 140},
    {"ECBackend::submit_transaction", 150},
    {"BlueStore::_txc_calc_cost", 160},
    {"ReplicatedBackend::repop_commit", 170},
    {"OpRequest::mark_flag_point", 180},
    {"BlueStore::log_latency_fn", 190}
};

std::map<std::string, int> func_progid = {
    {"OSD::enqueue_op", 0},
    {"OSD::dequeue_op", 1},
    {"PrimaryLogPG::execute_ctx", 2},
    {"ReplicatedBackend::submit_transaction", 3},
    {"BlueStore::queue_transactions", 4},
    {"BlueStore::_do_write", 5},
    {"BlueStore::_wctx_finish", 6},
    {"BlueStore::_txc_state_proc", 7},
    {"PrimaryLogPG::log_op_stats", 8},
    {"PrimaryLogPG::log_op_stats_v2", 9},
    {"ReplicatedBackend::generate_subop", 10},
    {"ReplicatedBackend::do_repop_reply", 11},
    {"OpRequest::mark_flag_point_string", 12},
    {"BlueStore::log_latency", 13},
    {"log_subop_stats", 14},
    {"ECBackend::submit_transaction", 15},
    {"BlueStore::_txc_calc_cost", 16},
    {"ReplicatedBackend::repop_commit", 17},
    {"OpRequest::mark_flag_point", 18},
    {"BlueStore::log_latency_fn", 19}
};

DwarfParser::probes_t osd_probes = {

    {"OSD::enqueue_op",
     {{"op", "px", "request", "header", "type"},
      {"op", "px", "reqid", "name", "_num"},
      {"op", "px", "reqid", "tid"},
      {"op", "px", "request", "recv_stamp"},
      {"op", "px", "request", "throttle_stamp"},
      {"op", "px", "request", "recv_complete_stamp"},
      {"op", "px", "request", "dispatch_stamp"}}},

    {"OSD::dequeue_op",
     {{"op", "px", "request", "header", "type"},
      {"op", "px", "reqid", "name", "_num"},
      {"op", "px", "reqid", "tid"},
      {"pg", "px", "pg_id", "pgid", "m_pool"},
      {"pg", "px", "pg_id", "pgid", "m_seed"}}},

    {"PrimaryLogPG::execute_ctx",
     {{"ctx", "reqid", "name", "_num"}, {"ctx", "reqid", "tid"}}},

    {"ReplicatedBackend::submit_transaction",
     {{"reqid", "name", "_num"}, {"reqid", "tid"}}},

    {"BlueStore::queue_transactions", {}},

    {"BlueStore::_do_write",
     {
         //{"txc"},
         //{"offset"},
         //{"length"}
     }},

    {"BlueStore::_wctx_finish",
     {
        {"txc", "osr", "px", "sequencer_id"},
        {"txc", "start", "__d", "__r"}
     }},

    {"BlueStore::_txc_calc_cost",
     {
        {"txc", "osr", "px", "sequencer_id"},
        {"txc", "start", "__d", "__r"}
     }},

    {"BlueStore::_txc_state_proc", 
     {{"txc", "osr", "px", "sequencer_id"},
      {"txc", "start", "__d", "__r"},
      {"txc", "state"},
      {"txc", "ioc", "num_pending"}}},

    {"BlueStore::_txc_apply_kv", {{"txc", "state"}}},

    {"PrimaryLogPG::log_op_stats",
     {{"op", "reqid", "name", "_num"},
      {"op", "reqid", "tid"},
      {"inb"},
      {"outb"},
      {"op", "request", "recv_stamp"},
      //{"op", "request", "throttle_stamp"},
      {"op", "request", "header", "type"}}},

    {"ReplicatedBackend::generate_subop",
     {{"reqid", "name", "_num"},
      {"reqid", "tid"},
      {"peer", "osd"}}},
    
    {"ReplicatedBackend::do_repop_reply",
      {{"op", "px", "reqid", "name", "_num"},
       {"op", "px", "reqid", "tid"},
       {"op", "px", "request", "header", "src", "num"}}},
    
    {"OpRequest::mark_flag_point_string",
     {{"flag"},
      {"this", "reqid", "name", "_num"},
      {"this", "reqid", "tid"},
      {"s", "_M_string_length"},
      {"s", "_M_dataplus", "_M_p"}}}, //refer to https://blog.csdn.net/qq_41540355/article/details/122182423
      //{"s", "_M_local_buf"}}}, // when size < 15
    
    {"BlueStore::log_latency",
     {{"idx"},
      {"l", "__r"}}},

    {"BlueStore::log_latency_fn",
     {{"idx"},
      {"l", "__r"}}},

    {"log_subop_stats", 
     {{"op", "px", "reqid", "name", "_num"},
      {"op", "px", "reqid", "tid"},
      {"op", "px", "request", "data", "_len"}}},
    
    {"ECBackend::submit_transaction",
     {{"reqid", "name", "_num"}, {"reqid", "tid"}}},

    {"ReplicatedBackend::repop_commit",
     {{"rm", "_M_ptr", "op", "px", "reqid", "name", "_num"},
      {"rm", "_M_ptr", "op", "px", "reqid", "tid"},
      {"rm", "_M_ptr", "op", "px", "request", "data", "_len"}}},

    {"OpRequest::mark_flag_point",
     {{"flag"},
      {"this", "reqid", "name", "_num"},
      {"this", "reqid", "tid"}}}
};

enum mode_e { MODE_AVG = 1, MODE_MAX, MODE_ALL };

enum mode_e mode = MODE_ALL;

enum probe_mode_e {
    OP_SINGLE_PROBE = 1,
    OP_FULL_PROBE = 2,
    BLUESTORE_PROBE = 4
};

int probe_mode = OP_FULL_PROBE;

static __u64 bootstamp = 0;

__u64 threshold = 0; //in millisecond
int timeout = -1; //in seconds

volatile sig_atomic_t timeout_occurred = 0;


static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
  if (level == LIBBPF_DEBUG) return 0;
  return vfprintf(stderr, format, args);
}

#define DEBUG printf

typedef struct peer_lat_t {
    int peer;
    __u64 latency;
    peer_lat_t(int a, __u64 b): peer(a), latency(b) {}
} peer_lat;

struct pgid_t {
  __u64 m_pool;
  __u32 m_seed;
};

typedef struct osd_op {
  __u16 type;
  __u32 wb;
  __u32 rb;

  __u64 client_id;
  __u64 req_id;
  struct pgid_t pg;

//Messenger level
  __u64 throttle_lat; //throttle_stamp - recv_stamp
  __u64 recv_lat;     //recv_complete_stamp - recv_stamp
  __u64 dispatch_lat; //enqueue_stamp - recv_complete_stamp

//OSD level
  __u64 queue_lat;
  __u32 delayed_cnt;
  std::vector<std::string> delayed_strs;
  __u64 osd_lat;
  //__u32 onode_decode;
  //__u32 extent_decode;

//Peer info
  vector<peer_lat> peers;

//Bluestore level
  __u64 bs_prepare_lat; //including space allocation, 4k aligning..
  __u64 bs_aio_wait_lat;
  __u64 bs_pg_seq_lat;  //The time to wait for previous ops's aio to the same PG to finish
  __u64 bs_kv_commit_lat;
  __u64 bs_lat;  
  int aio_size;

// op lat
  __u64 op_lat;
} osd_op_t;

int num_osd = 0;
int osds[MAX_OSD] = {0};
int pids[MAX_OSD] = {0};

//@write
//(0, 4k) num {min=, max=, avg=, 10%=, 50%=, 90%=, 95%=, 99%=, 99.9%=}
//[4k, 8k) 
//...
//
//@read
//(0, 4k) num {min=, max=, avg=, 10%=, 50%=, 90%=, 95%=, 99%=, 99.9%=}
//[4k, 8k) 
//...
std::vector<string> size_ranges = {"(0, 4k)", 
                                   "[4k, 8k)", 
                                   "[8K, 16k)",
                                   "[16k, 32k)",
                                   "[32k, 64k)",
                                   "[64k, 128k)",
                                   "[128k, 256k)",
                                   "[256k, 512k)",
                                   "[512k, 1M)",
                                   "[1M, )"
                                  };
typedef std::vector<std::vector<__u64>> SizeRangeLatVec;   
std::map<int, SizeRangeLatVec> osd_wsrl, osd_rsrl;

int exists(int id) {
  for (int i = 0; i < num_osd; ++i) {
    if (osds[i] == id) return 1;
  }
  return 0;
}

int osd_pid_to_id(__u32 pid) {
  for (int i = 0; i < num_osd; ++i) {
    if (pids[i] == (int)pid) {
      return osds[i];
    }
  }
  // First time, read from /proc/<pid>/cmdline
  char path_cmdline[50];
  char pname[200];
  int id = -1;
  memset(path_cmdline, 0, sizeof(path_cmdline));
  memset(pname, 0, sizeof(pname));
  snprintf(path_cmdline, sizeof(path_cmdline), "/proc/%d/cmdline", pid);
  int fd = open(path_cmdline, O_RDONLY);
  if (fd >= 0 && read(fd, pname, 199) > 0) {
    // Find "--id" or "-i" or "-n osd.<id>" followed by OSD ID in the cmdline
    // cmdline has null-separated arguments
    for (int i = 0; i < 195; ++i) {
      // Check for "--id\0"
      if (pname[i] == '-' && pname[i+1] == '-' && pname[i+2] == 'i' && pname[i+3] == 'd' && pname[i+4] == '\0') {
        // Found "--id\0", OSD ID starts after the null byte
        int start = i + 5;
        id = 0;
        while (start < 200 && pname[start] >= '0' && pname[start] <= '9') {
          id *= 10;
          id += pname[start] - '0';
          ++start;
        }
        break;
      }
      // Check for "-i\0"
      else if (pname[i] == '-' && pname[i+1] == 'i' && pname[i+2] == '\0') {
        // Found "-i\0", OSD ID starts after the null byte
        int start = i + 3;
        id = 0;
        while (start < 200 && pname[start] >= '0' && pname[start] <= '9') {
          id *= 10;
          id += pname[start] - '0';
          ++start;
        }
        break;
      }
      // Check for "-n\0" followed by "osd.<id>\0"
      else if (pname[i] == '-' && pname[i+1] == 'n' && pname[i+2] == '\0') {
        // Found "-n\0", check if next argument starts with "osd."
        int start = i + 3;
        if (start + 4 < 200 && pname[start] == 'o' && pname[start+1] == 's' && pname[start+2] == 'd' && pname[start+3] == '.') {
          // Found "osd.", extract ID between "osd." and '\0'
          start += 4; // Move past "osd."
          id = 0;
          while (start < 200 && pname[start] >= '0' && pname[start] <= '9') {
            id *= 10;
            id += pname[start] - '0';
            ++start;
          }
          break;
        }
      }
    }
    close(fd);
  }
  return id;
}

__u64 to_ns(struct timespec *ts) {
  return ts->tv_nsec + (ts->tv_sec * 1000000000ull);
}

__u64 to_us(struct timespec *ts) {
  return (ts->tv_nsec / 1000) + (ts->tv_sec * 1000000ull);
}

__u64 to_ms(struct timespec *ts) {
  return (ts->tv_nsec / 1000000) + (ts->tv_sec * 1000);
}

void timespec_diff(struct timespec *start, struct timespec *stop,
                   struct timespec *result) {
  if ((stop->tv_nsec - start->tv_nsec) < 0) {
    result->tv_sec = stop->tv_sec - start->tv_sec - 1;
    result->tv_nsec = stop->tv_nsec - start->tv_nsec + 1000000000;
  } else {
    result->tv_sec = stop->tv_sec - start->tv_sec;
    result->tv_nsec = stop->tv_nsec - start->tv_nsec;
  }

  return;
}

__u64 timespec_sub_ms(struct timespec *a, struct timespec *b) {
  struct timespec c;
  timespec_diff(b, a, &c);
  return to_ms(&c);
}

__u64 get_bootstamp() {
  struct timespec realtime, boottime, prevtime;
  clock_gettime(CLOCK_REALTIME, &realtime);
  clock_gettime(CLOCK_BOOTTIME, &boottime);
  timespec_diff(&boottime, &realtime, &prevtime);

  return (prevtime.tv_sec * 1000000000ull) + prevtime.tv_nsec;
}


int knum(__u64 x) {
    return x / 1024;
}

int lsb (int x) {
    int r = 0;
    while (x > 0) {
	r++;
	x = x >> 1;
    }
    return r;
}

int index(int k) {
    int b = lsb(k);
    if (b <= 2)
	return 0;
    else 
	return min(10, b - 2); 
}

void handle_single(struct op_v *val, int osd_id) {
  auto &wvecs = osd_wsrl[osd_id];
  if(wvecs.empty()) {
    wvecs.resize(11);
  }

  auto &rvecs = osd_rsrl[osd_id];
  if(rvecs.empty()) {
    rvecs.resize(11);
  }
  if (val->recv_stamp == 0) {//TODO weird bug, occationaly, 1/10000 of the ops could have recv_stamp==0
    return ;
  }
  __u64 op_lat = (val->reply_stamp - (val->recv_stamp - bootstamp)); 
  __u64 wb = val->wb;
  __u64 rb = val->rb;
  int k, idx;
  if (wb > 0) {
    k = knum(wb);
    idx = index(k);
    wvecs[idx].push_back(op_lat);
  } else if (rb > 0) {
    k = knum(rb);
    idx = index(k);
    rvecs[idx].push_back(op_lat);
  } else {
      //TODO operation to access object omap or xattr
      //
  }
  //printf("osd %d inb %lld, oub %lld, op latency %lld recv_stamp %lld recv_stamp - boot_stamp %lld reply_stamp %lld\n", osd_id, wb, rb, op_lat, val->recv_stamp, val->recv_stamp - bootstamp, val->reply_stamp);

}

void print_lat_dist(std::vector<__u64> v, int l) {
  printf("min=%lld ", v[0] / 1000);	
  printf("max=%lld ", v[l-1] / 1000);	
  __u64 sum = 0;
  for (auto x : v) {
    sum += x / 1000;
  }
  __u64 avg = sum / l;
  printf("avg=%lld ", avg);
  printf("10.00th=%lld ", v[l * 0.1]/1000);
  printf("50.00th=%lld ", v[l * 0.5]/1000);
  printf("90.00th=%lld ", v[l * 0.9]/1000);
  printf("95.00th=%lld ", v[l * 0.95]/1000);
  printf("99.00th=%lld ", v[l * 0.99]/1000);
  printf("99.50th=%lld ", v[l * 0.995]/1000);
}


void print_srl(int osd) {
  auto wvecs = osd_wsrl[osd];
  auto rvecs = osd_rsrl[osd];
  size_t idx = 0;
  printf("OSD %d\n", osd);
  printf("@write:\n");
  for (auto wv: wvecs) {
    if (idx == size_ranges.size())
      break;
    int l = wv.size();
    printf("%s | %d | ", size_ranges[idx].c_str(), l);
    sort(wv.begin(), wv.end());
    if(l > 0) {
      print_lat_dist(wv, l);
    }
    printf("\n");
    idx++;
  }

  printf("@read:\n");
  idx = 0;
  for (auto rv: rvecs) {
    if (idx == size_ranges.size())
      break;
    int l = rv.size();
    printf("%s | %d |", size_ranges[idx].c_str(), l);
    sort(rv.begin(), rv.end());
    if(l > 0) {
      print_lat_dist(rv, l);	
    }
    printf("\n");
    idx++;
  } 
}

void print_all_srl() {
  for (int id = 0; id < num_osd; ++id) {
    print_srl(osds[id]);
    printf("\n\n");
  }
}

void print_op_r(osd_op_t &op, int osd_id) {
  std::stringstream ss;
  ss << std::hex << op.pg.m_seed;
  std::string pgid(ss.str());

  printf("osd %d pg %lld.%s op_r " 
         "size %d client %lld tid %lld "
	 "throttle_lat %lld recv_lat %lld dispatch_lat %lld "
	 "queue_lat %lld osd_lat %lld "
	 "bluestore_lat %lld "
	 "op_lat %lld \n",
   	  osd_id, op.pg.m_pool, pgid.c_str(), 
	  op.rb, op.client_id, op.req_id,
	  op.throttle_lat, op.recv_lat, op.dispatch_lat, 
	  op.queue_lat, op.osd_lat,
	  op.bs_lat, 
	  op.op_lat);
  for (__u32 i = 0; i < op.delayed_cnt; ++i) {
    printf("[delayed%d %s ]", i+1, op.delayed_strs[i].c_str());
  }
  if (op.delayed_cnt > 0)
    printf("\n");
}

void print_subop_w(osd_op_t &op, int osd_id) {
  std::stringstream ss;
  ss << std::hex << op.pg.m_seed;
  std::string pgid(ss.str());

  printf("osd %d pg %lld.%s subop_w " 
         "size %d client %lld tid %lld "
	 "throttle_lat %lld recv_lat %lld dispatch_lat %lld "
	 "queue_lat %lld osd_lat %lld "
	 "bluestore_lat %lld (prepare %lld aio_wait %lld (aio_size %d) seq_wait %lld kv_commit %lld) "
	 "subop_lat %lld \n",
   	  osd_id, op.pg.m_pool, pgid.c_str(), 
	  op.wb, op.client_id, op.req_id,
	  op.throttle_lat, op.recv_lat, op.dispatch_lat, 
	  op.queue_lat, op.osd_lat,
	  op.bs_lat, op.bs_prepare_lat, op.bs_aio_wait_lat, op.aio_size, op.bs_pg_seq_lat, op.bs_kv_commit_lat, 
	  op.op_lat);
  for (__u32 i = 0; i < op.delayed_cnt; ++i) {
    printf("[delayed%d %s ]", i+1, op.delayed_strs[i].c_str());
  }
  if (op.delayed_cnt > 0)
    printf("\n");
}

void print_op_w(osd_op_t &op, int osd_id) {

  std::stringstream ss;
  ss << std::hex << op.pg.m_seed;
  std::string pgid(ss.str());

  printf("osd %d pg %lld.%s op_w " 
         "size %d client %lld tid %lld "
	 "throttle_lat %lld recv_lat %lld dispatch_lat %lld "
	 "queue_lat %lld osd_lat %lld peers [(%d, %lld), (%d, %lld)] "
	 "bluestore_lat %lld (prepare %lld aio_wait %lld (aio_size %d) seq_wait %lld kv_commit %lld) "
	 "op_lat %lld \n",
   	  osd_id, op.pg.m_pool, pgid.c_str(), 
	  op.wb, op.client_id, op.req_id,
	  op.throttle_lat, op.recv_lat, op.dispatch_lat, 
	  op.queue_lat, op.osd_lat,  op.peers[0].peer, op.peers[0].latency, op.peers[1].peer, op.peers[1].latency, 
	  op.bs_lat, op.bs_prepare_lat, op.bs_aio_wait_lat, op.aio_size, op.bs_pg_seq_lat, op.bs_kv_commit_lat, 
	  op.op_lat);
  for (__u32 i = 0; i < op.delayed_cnt; ++i) {
    printf("[delayed%d %s ]", i+1, op.delayed_strs[i].c_str());
  }
  if (op.delayed_cnt > 0)
    printf("\n");
}

void signal_handler(int signum){
  clog << "Caught signal " << signum << endl;
  if (signum == SIGINT) {
      print_all_srl();
  }
  exit(signum);
}

void timeout_handler(int signum) {
    if (signum == SIGALRM) {
        timeout_occurred = 1;
    }
}

osd_op_t generate_op(op_v *val) {
  osd_op_t op = osd_op_t();

  op.type = val->op_type;

  op.wb = val->wb;
  op.rb = val->rb;
  
  op.client_id = val->owner;
  op.req_id = val->tid;

  op.pg.m_pool = val->m_pool;
  op.pg.m_seed = val->m_seed;

  __u64 recv_stamp = val->recv_stamp;
  if (val->throttle_stamp < val->recv_stamp) { 
      //Due to recv_stamp bug https://tracker.ceph.com/issues/52739
      //Releases older than 16.2.7, the recv_stamp is not accurate at all
      //Hence we'll use the throttle_stamp as the recv_stamp, which will only lose 1-3 microseconds
      recv_stamp = val->throttle_stamp;

  }
  op.throttle_lat = (val->throttle_stamp - recv_stamp)/1000; 
  op.recv_lat = (val->recv_complete_stamp - recv_stamp)/1000; 
  op.dispatch_lat +=
      (val->enqueue_stamp - (val->recv_complete_stamp - bootstamp))/1000;

  op.queue_lat += (val->dequeue_stamp - val->enqueue_stamp)/1000;

  if (op.wb > 0)
    op.osd_lat = (val->queue_transaction_stamp - val->dequeue_stamp)/1000;
  else if (op.rb > 0)
    op.osd_lat = (val->execute_ctx_stamp - val->dequeue_stamp) /1000;

  op.delayed_cnt = val->di.cnt;
  for(int i = 0; i < val->di.cnt; ++i) {
    op.delayed_strs.push_back(std::string(val->di.delays[i]));
  }
  if (op.type == MSG_OSD_OP) {
    op.peers.push_back(peer_lat(val->pi.peer1, (val->pi.recv_stamp1 - val->pi.sent_stamp)/1000));
    op.peers.push_back(peer_lat(val->pi.peer2, (val->pi.recv_stamp2 - val->pi.sent_stamp)/1000)); 
  }
  //bluestore level
  op.aio_size = val->aio_size;
  op.bs_prepare_lat = (val->aio_submit_stamp - val->queue_transaction_stamp)/1000;
  op.bs_aio_wait_lat = (val->aio_done_stamp - val->aio_submit_stamp)/1000;
  op.bs_pg_seq_lat = (val->kv_submit_stamp - val->aio_done_stamp)/1000;
  op.bs_kv_commit_lat = (val->kv_committed_stamp - val->kv_submit_stamp)/1000;
  if (op.wb > 0)
    op.bs_lat = (val->kv_committed_stamp - val->queue_transaction_stamp)/1000;
  else if (op.rb > 0)
    op.bs_lat = (val->reply_stamp - val->execute_ctx_stamp)/1000;

  op.op_lat = (val->reply_stamp - (recv_stamp - bootstamp))/1000;

  return op;
}

void handle_full(struct op_v *val, int osd_id) {
    //if (val->wb == 0)
      //return;
    osd_op_t op = generate_op(val);
    if (op.op_lat/(1000) < threshold)
      return;
    if (op.wb == 0) {
      print_op_r(op, osd_id);
    } else if (op.type == MSG_OSD_OP) {
      print_op_w(op, osd_id);
    } else if (op.type == MSG_OSD_REPOP) {
      print_subop_w(op, osd_id);
    } else {
      printf("unsupported op type %d\n", op.type);
    }
}



void handle_bluestore(struct bluestore_lat_v *val, int osd_id) {
    __u64 lat_us = val->lat / 1000;
    // The `name` argument captured from the probe is the authoritative,
    // version-stable label for the operation.
    const char *name = val->name[0] ? val->name : "?";
    printf("osd %d bluestore %s lat %lld us\n", osd_id, name, lat_us);
}

static int handle_event(void *ctx, void *data, size_t size) {
  (void)ctx;
  int osd_id = -1;
  int pid = 0;

  // Determine event type based on size
  bool is_bluestore_event = (size == sizeof(struct bluestore_lat_v));
  bool is_op_event = (size == sizeof(struct op_v));

  if (is_op_event && (probe_mode & (OP_SINGLE_PROBE | OP_FULL_PROBE))) {
    struct op_v *val = (struct op_v *)data;
    pid = val->pid;
    osd_id = osd_pid_to_id(pid);

    if (probe_mode == OP_SINGLE_PROBE) {
      handle_single(val, osd_id);
    } else if (probe_mode & OP_FULL_PROBE) {
      handle_full(val, osd_id);
    }
  } else if (is_bluestore_event && (probe_mode & BLUESTORE_PROBE)) {
    struct bluestore_lat_v *val = (struct bluestore_lat_v *) data;
    pid = val->pid;
    osd_id = osd_pid_to_id(pid);
    handle_bluestore(val, osd_id);
  }

  if (!exists(osd_id)) {
    osds[num_osd] = osd_id;
    pids[num_osd++] = pid;
  }
  return 0;
}

/*
static void handle_lost_event(void *ctx, int cpu, __u64 lost_cnt)
{
        printf("lost %llu events on cpu %d\n", lost_cnt, cpu);
}
*/

std::string json_input_file;
std::string json_output_file;
bool import_json = false;
bool export_json = false;
bool skip_version_check = false;
bool list_only = false;
bool list_embedded = false;
bool trace_all = false;

struct OsdProcessInfo {
  int pid;
  int osd_id;
  std::string exe_path;
  bool is_container;
  // Embedded-DWARF traceability verdict, populated lazily by
  // annotate_traceability() for the --list path only: "yes", "no", "unknown"
  // (empty until computed).
  std::string traceable;
  // Ceph package version, populated alongside `traceable` by
  // annotate_traceability() for the --list path only.  Authoritative when
  // traceable=="yes" (taken from the matched embedded entry); best-effort host
  // package query for a non-container, non-traceable OSD; "unknown" otherwise.
  std::string version;
  // ELF build-id of the binary the uprobes would attach to (read through
  // /proc/<pid>/root so containers resolve to the in-container binary).
  // Populated by annotate_traceability(); used by -a to group processes that
  // share a single build, since the BPF probe offsets are version-specific.
  std::string build_id;
};

std::string get_mnt_ns(int pid) {
  char link_target[256];
  std::string ns_path = "/proc/" + std::to_string(pid) + "/ns/mnt";
  ssize_t len = readlink(ns_path.c_str(), link_target, sizeof(link_target) - 1);
  if (len != -1) {
    link_target[len] = '\0';
    return std::string(link_target);
  }
  return "";
}

std::vector<OsdProcessInfo> discover_ceph_osd_processes() {
  std::vector<OsdProcessInfo> results;
  DIR* proc_dir = opendir("/proc");
  if (!proc_dir) {
    std::cerr << "Error: Could not open /proc directory" << std::endl;
    return results;
  }

  std::string self_ns = get_mnt_ns(getpid());

  struct dirent* entry;
  while ((entry = readdir(proc_dir)) != NULL) {
    if (entry->d_type == DT_DIR && isdigit(entry->d_name[0])) {
      int pid = 0;
      try {
        pid = std::stoi(entry->d_name);
      } catch (...) {
        continue;
      }

      std::string exe_path = get_exe_path_for_pid(pid);
      if (exe_path.empty()) {
        // Fallback: read first argument from /proc/<pid>/cmdline
        std::string cmdline_path = "/proc/" + std::to_string(pid) + "/cmdline";
        std::ifstream cmd_file(cmdline_path, std::ios::binary);
        if (cmd_file) {
          std::getline(cmd_file, exe_path, '\0');
        }
      }

      if (!exe_path.empty()) {
        std::string basename = get_basename(exe_path);
        if (basename == "ceph-osd") {
          int osd_id = osd_pid_to_id(pid);
          
          bool is_container = false;
          std::string proc_ns = get_mnt_ns(pid);
          if (!self_ns.empty() && !proc_ns.empty() && self_ns != proc_ns) {
            is_container = true;
          }
          
          results.push_back({pid, osd_id, exe_path, is_container, "", "", ""});
        }
      }
    }
  }
  closedir(proc_dir);

  // Sort primarily by OSD ID, then by PID
  std::sort(results.begin(), results.end(), [](const OsdProcessInfo& a, const OsdProcessInfo& b) {
    if (a.osd_id != b.osd_id) {
      return a.osd_id < b.osd_id;
    }
    return a.pid < b.pid;
  });

  return results;
}

void print_discovered_osds(const std::vector<OsdProcessInfo>& processes,
                           bool show_traceable = false) {
  if (show_traceable) {
    printf("  %-10s %-10s %-12s %-11s %-24s\n", "PID", "OSD ID", "Container", "Traceable", "Ceph Version");
    printf("  -----------------------------------------------------------------------\n");
  } else {
    printf("  %-10s %-10s %-12s %-50s\n", "PID", "OSD ID", "Container", "Executable Path");
    printf("  --------------------------------------------------------------------------------\n");
  }
  for (const auto& proc : processes) {
    std::string osd_id_str = (proc.osd_id == -1) ? "unknown" : std::to_string(proc.osd_id);
    std::string container_str = proc.is_container ? "yes" : "no";
    if (show_traceable) {
      std::string traceable_str = proc.traceable.empty() ? "unknown" : proc.traceable;
      std::string version_str = proc.version.empty() ? "unknown" : proc.version;
      printf("  %-10d %-10s %-12s %-11s %-24s\n", proc.pid, osd_id_str.c_str(),
             container_str.c_str(), traceable_str.c_str(), version_str.c_str());
    } else {
      printf("  %-10d %-10s %-12s %-50s\n", proc.pid, osd_id_str.c_str(), container_str.c_str(), proc.exe_path.c_str());
    }
  }
}

// Fill in each process's `traceable` verdict by reading the build-id of the
// binary the uprobes would attach to (bridged through /proc/<pid>/root so
// containerized OSDs resolve to the in-container binary) and checking it
// against the compiled-in embedded DWARF table.  Reading another process's
// (or a container's) binary requires root; otherwise the verdict is "unknown".
void annotate_traceability(std::vector<OsdProcessInfo>& processes) {
  for (auto& proc : processes) {
    proc.version = "unknown";
    std::string bridged_path = "/proc/" + std::to_string(proc.pid) + "/root" + proc.exe_path;
    std::string build_id = get_elf_build_id(bridged_path);
    proc.build_id = build_id;
    if (build_id.empty()) {
      proc.traceable = "unknown";
      continue;
    }
    std::string matched;
    bool ok = DwarfParser::is_embedded_traceable(
        {{get_basename(proc.exe_path), build_id}}, "osdtrace", &matched);
    proc.traceable = ok ? "yes" : "no";
    if (ok) {
      // Authoritative: the matched embedded entry's version is exactly the
      // package this binary was built from.
      if (!matched.empty()) proc.version = matched;
    } else if (!proc.is_container &&
               !check_executable_deleted(proc.pid, "ceph-osd")) {
      // Best-effort for a native (non-container) OSD whose running binary still
      // matches what's on disk: query the host package DB.  We skip containers
      // (host DB describes the host, not the container) and skip processes
      // whose on-disk binary was replaced after launch (the deleted-exe check),
      // since the package DB would then report a version we aren't running.
      std::string pkg = get_package_version(proc.exe_path);
      if (!pkg.empty() && pkg != "unknown") proc.version = pkg;
    }
  }
}

std::set<int> process_ids;  // Support multiple PIDs (set ensures deduplication)
std::set<int> requested_osd_ids;  // Populated by --id; resolved to PIDs in main()
int parse_args(int argc, char **argv) {
  static struct option long_options[] = {
    {"skip-version-check", no_argument, 0, 0},
    {"version", no_argument, 0, 'V'},
    {"list", no_argument, 0, 0},
    {"list-embedded", no_argument, 0, 0},
    {"id", required_argument, 0, 0},
    {"all", no_argument, 0, 'a'},
    {0, 0, 0, 0}
  };

  int option_index = 0;
  // getopt_long() returns int and uses -1 to signal end-of-options; storing
  // it in a plain char is unsafe on platforms where char is unsigned by
  // default (the `!= -1` test can then loop forever).  Match kfstrace.
  int opt;
  while ((opt = getopt_long(argc, argv, ":st:bj:i:l:p:Va", long_options, &option_index)) != -1) {
    switch (opt) {
      case 0:
        // Handle long options
        if (strcmp(long_options[option_index].name, "skip-version-check") == 0) {
          skip_version_check = true;
        } else if (strcmp(long_options[option_index].name, "list") == 0) {
          list_only = true;
        } else if (strcmp(long_options[option_index].name, "list-embedded") == 0) {
          list_embedded = true;
        } else if (strcmp(long_options[option_index].name, "id") == 0) {
          std::stringstream ss(optarg);
          std::string token;
          while (std::getline(ss, token, ',')) {
            try {
              int id = stoi(token);
              if (id < 0) {
                std::cerr << "Invalid --id value (must be non-negative): " << token << std::endl;
                return -1;
              }
              requested_osd_ids.insert(id);
            } catch (...) {
              std::cerr << "Invalid --id value: " << token << std::endl;
              return -1;
            }
          }
        }
        break;
      case 'V':
        print_tool_version("osdtrace");
        exit(0);

      case 'a':
        trace_all = true;
        break;
      case 's':
        probe_mode &= ~OP_FULL_PROBE;
        probe_mode |= OP_SINGLE_PROBE;
        break;
      case 'l':
        threshold = stoi(optarg);
        break;
      case 'b':
        probe_mode |= BLUESTORE_PROBE;
        break;
      case 'j':
        export_json = true;
        json_output_file = optarg;
        break;
      case 'i':
        import_json = true;
        json_input_file = optarg;
        break;
      case 't':
        try {
            timeout = stoi(optarg);
            if (timeout <= 0) throw std::invalid_argument("Negative timeout");
        } catch (...) {
            std::cerr << "Invalid timeout value. Must be a positive integer.\n";
            exit(1);
        }
        break;
      case 'p':
        {
          std::string pid_str(optarg);
          std::stringstream ss(pid_str);
          std::string token;
          while (std::getline(ss, token, ',')) {
            try {
              int pid = stoi(token);
              process_ids.insert(pid);
            } catch (...) {
              std::cerr << "Invalid PID value: " << token << std::endl;
              return -1;
            }
          }
        }
        break;
      case '?':
      case 'h':
        std::cout << "Usage: " << argv[0] << " [-s] [-l <milliseconds>] [-b] [-j] [-i <filename>] [-t <seconds>] [-a] [-p <pid1,pid2,...>] [--id <osd-id1,osd-id2,...>] [--skip-version-check] [--list] [--list-embedded]\n";
        std::cout << "  -s                        Set probe mode to Single OP (logs PrimaryLogPG::log_op_stats only)\n";
        std::cout << "  -l <milliseconds>         Set operation latency threshold to capture\n";
        std::cout << "  -b                        Set probe mode to Bluestore\n";
        std::cout << "  -j                        Export DWARF info to JSON file\n";
        std::cout << "  -i <filename>             Import DWARF info from JSON file\n";
        std::cout << "  -t <seconds>              Set execution timeout in seconds\n";
        std::cout << "  -a, --all                 Trace ALL traceable ceph-osd processes on the host (native and containerized)\n";
        std::cout << "  -p <pid1,pid2,...>        Probe using Process IDs (comma-separated, mandatory for tracing containerized processes)\n";
        std::cout << "  --id <osd-id1,osd-id2,...> Probe by OSD ID (comma-separated; resolves to PIDs via discovery)\n";
        std::cout << "  --skip-version-check      Skip version check when importing DWARF JSON (currently needed for containers)\n";
        std::cout << "  --list                    List active ceph-osd processes on the host, their PIDs and OSD IDs, and exit\n";
        std::cout << "  --list-embedded           List the Ceph versions with DWARF data compiled into this binary, and exit\n";
        std::cout << "  -V, --version             Print version information and exit\n";
        std::cout << "  -h                        Show this help message\n";
        exit(0);
      case ':':
        clog << "Missing arg for " << optopt << endl;
        return -1;
    }
  }
  return 0;
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

int attach_uprobe(struct osdtrace_bpf *skel,
                 DwarfParser &dp,
                 std::string path,
                 int process_id,
                 std::string funcname,
                 int v = 0) {

  std::string path_basename = get_basename(path);
  auto &func2pc = dp.mod_func2pc[path_basename];
  size_t func_addr = func2pc[funcname];
  if (func_addr == 0) {
    cerr << "Warning: func_addr is zero for " << funcname << " in " << path << ", skipping uprobe" << endl;
    return -1;
  }
  if (v > 0)
      funcname = funcname + "_v" + std::to_string(v);
  int pid = func_progid[funcname];

  std::string attach_path = (process_id == -1) ? path : "/proc/" + std::to_string(process_id) + "/root/" + path;
  struct bpf_link *ulink = bpf_program__attach_uprobe(
      *skel->skeleton->progs[pid].prog,
      false /* not uretprobe */,
      process_id,
      attach_path.c_str(), func_addr);
  if (!ulink) {
    if (process_id == -1)
      cerr << "Failed to attach uprobe to " << funcname << endl;
    else
      cerr << "Failed to attach uprobe to " << funcname << " for PID " << process_id << endl;
    return -errno;
  }
  if (process_id == -1)
    clog << "uprobe " << funcname << " attached to all processes" << endl;
  else
    clog << "uprobe " << funcname << " attached to PID " << process_id << endl;
  return 0;
}

int attach_uprobes(struct osdtrace_bpf *skel,
                  DwarfParser &dp,
                  std::string path,
                  const std::set<int> &process_ids,
                  std::string funcname,
                  int v = 0) {
  if (process_ids.empty())
    return attach_uprobe(skel, dp, path, -1, funcname, v);
  for (auto pid : process_ids) {
    int ret = attach_uprobe(skel, dp, path, pid, funcname, v);
    if (ret < 0) return ret;
  }
  return 0;
}

int attach_retuprobe(struct osdtrace_bpf *skel,
	           DwarfParser &dp,
	           std::string path,
                   int process_id,
		   std::string funcname,
		   int v = 0) {
  std::string path_basename = get_basename(path);
  auto &func2pc = dp.mod_func2pc[path_basename];
  size_t func_addr = func2pc[funcname];
  if (func_addr == 0) {
    cerr << "Warning: func_addr is zero for " << funcname << " in " << path << ", skipping uretprobe" << endl;
    return -1;
  }
  if (v > 0)
      funcname = funcname + "_v" + std::to_string(v);
  int pid = func_progid[funcname];

  std::string attach_path = (process_id == -1) ? path : "/proc/" + std::to_string(process_id) + "/root/" + path;
  struct bpf_link *ulink = bpf_program__attach_uprobe(
      *skel->skeleton->progs[pid].prog,
      true /* uretprobe */,
      process_id,
      attach_path.c_str(), func_addr);
  if (!ulink) {
    if (process_id == -1)
      cerr << "Failed to attach uretprobe to " << funcname << endl;
    else
      cerr << "Failed to attach uretprobe to " << funcname << " for PID " << process_id << endl;
    return -errno;
  }
  if (process_id == -1)
    clog << "uretprobe " << funcname << " attached to all processes" << endl;
  else
    clog << "uretprobe " << funcname << " attached to PID " << process_id << endl;
  return 0;
}

int attach_retuprobes(struct osdtrace_bpf *skel,
                     DwarfParser &dp,
                     std::string path,
                     const std::set<int> &process_ids,
                     std::string funcname,
                     int v = 0) {
  if (process_ids.empty())
    return attach_retuprobe(skel, dp, path, -1, funcname, v);
  for (auto pid : process_ids) {
    int ret = attach_retuprobe(skel, dp, path, pid, funcname, v);
    if (ret < 0) return ret;
  }
  return 0;
}

int main(int argc, char **argv) {
  signal(SIGINT, signal_handler);

  if (parse_args(argc, argv) < 0) return 0;

  if (list_embedded) {
    DwarfParser::list_embedded_versions("osdtrace");
    return 0;
  }

  if (list_only) {
    if (geteuid() != 0) {
      std::cout << "Warning: Running without root privileges. Containerized status of OSDs owned by other users may not be accurately detected." << std::endl << std::endl;
    }
    auto processes = discover_ceph_osd_processes();
    if (processes.empty()) {
      std::cout << "No active ceph-osd processes detected on the host." << std::endl;
    } else {
      annotate_traceability(processes);
      std::cout << "Detected " << processes.size() << " active ceph-osd process(es) on the host:" << std::endl;
      print_discovered_osds(processes, /*show_traceable=*/true);

      // If any OSD isn't directly traceable, tell the user how to proceed.
      bool any_no = false, any_unknown = false;
      for (const auto& proc : processes) {
        if (proc.traceable == "no") any_no = true;
        else if (proc.traceable == "unknown") any_unknown = true;
      }
      if (any_no || any_unknown) {
        std::cout << std::endl
                  << "Traceable: 'yes' means this osdtrace already has matching DWARF data built in." << std::endl;
        if (any_no) {
          std::cout << "  'no':      no embedded DWARF matches this binary's build-id. Export a DWARF JSON" << std::endl;
          std::cout << "             on a host that has the matching ceph-osd (osdtrace -j <file>), then trace" << std::endl;
          std::cout << "             with: osdtrace -p <pid> -i <file> --skip-version-check" << std::endl;
        }
        if (any_unknown) {
          std::cout << "  'unknown': could not read the OSD binary's build-id; re-run as root" << std::endl;
          std::cout << "             (required for containerized OSDs)." << std::endl;
        }
        std::cout << std::endl
                  << "Ceph Version: authoritative when Traceable='yes' (the matched embedded entry)." << std::endl;
        std::cout << "             For Traceable='no' it is a best-effort host package lookup, shown only" << std::endl;
        std::cout << "             for native OSDs whose on-disk binary still matches the running process;" << std::endl;
        std::cout << "             'unknown' for containerized OSDs or binaries upgraded since launch." << std::endl;
      }
    }
    return 0;
  }

  // -a / --all: trace every traceable ceph-osd process on the host (native and
  // containerized).  Discover all OSDs, keep the ones this binary has matching
  // embedded DWARF for, and feed their PIDs into the normal multi-PID flow.
  //
  // The BPF probe offsets are version-specific (one hprobes map, one set of
  // function addresses per run), so -a assumes every traceable OSD shares a
  // single build.  If the traceable OSDs span more than one build-id we can't
  // trace them correctly in one run, so give up and ask the user to select a
  // single-build subset with -p/--id.
  if (trace_all) {
    if (!process_ids.empty() || !requested_osd_ids.empty()) {
      std::cerr << "Error: -a/--all cannot be combined with -p or --id" << std::endl;
      return 1;
    }
    if (export_json || import_json) {
      std::cerr << "Error: -a/--all cannot be combined with -j or -i" << std::endl;
      return 1;
    }
    if (geteuid() != 0) {
      std::cerr << "Warning: not running as root; containerized OSDs (and OSDs"
                << " owned by other users) may be missed or show as untraceable." << std::endl;
    }

    auto processes = discover_ceph_osd_processes();
    if (processes.empty()) {
      std::cerr << "No active ceph-osd processes detected on the host." << std::endl;
      return 1;
    }
    annotate_traceability(processes);

    std::vector<OsdProcessInfo> traceable, not_traceable;
    for (const auto& p : processes) {
      if (p.traceable == "yes" && !p.build_id.empty())
        traceable.push_back(p);
      else
        not_traceable.push_back(p);
    }

    if (traceable.empty()) {
      std::cerr << "Error: none of the " << processes.size()
                << " ceph-osd process(es) are traceable with this osdtrace's"
                << " embedded DWARF data." << std::endl;
      print_discovered_osds(processes, /*show_traceable=*/true);
      std::cerr << std::endl
                << "Export a DWARF JSON on a host with the matching ceph-osd"
                << " (osdtrace -j <file>), then trace with -p <pid> -i <file>"
                << " --skip-version-check." << std::endl;
      return 1;
    }

    // -a assumes a single build across all traceable OSDs; bail out otherwise.
    const std::string& build_id = traceable.front().build_id;
    for (const auto& p : traceable) {
      if (p.build_id != build_id) {
        std::cerr << "Error: traceable ceph-osd processes span more than one"
                  << " build; -a cannot trace multiple builds in one run."
                  << std::endl;
        print_discovered_osds(traceable, /*show_traceable=*/true);
        std::cerr << std::endl
                  << "Trace a single-build subset explicitly with -p <pid,...>"
                  << " or --id <osd-id,...>." << std::endl;
        return 1;
      }
    }

    for (const auto& p : traceable) process_ids.insert(p.pid);

    std::cout << "Tracing " << process_ids.size()
              << " ceph-osd process(es) selected by -a:" << std::endl;
    print_discovered_osds(traceable, /*show_traceable=*/true);
    if (!not_traceable.empty()) {
      std::cout << std::endl << "Skipping " << not_traceable.size()
                << " non-traceable ceph-osd process(es):" << std::endl;
      print_discovered_osds(not_traceable, /*show_traceable=*/true);
    }
    std::cout << std::endl;
  }

  // Resolve --id <osd-id,...> to PIDs via discovery and feed into process_ids.
  if (!requested_osd_ids.empty()) {
    if (!process_ids.empty()) {
      std::cerr << "Error: --id and -p are mutually exclusive" << std::endl;
      return 1;
    }
    auto processes = discover_ceph_osd_processes();
    for (int want : requested_osd_ids) {
      std::vector<int> matches;
      for (const auto& p : processes) {
        if (p.osd_id == want) matches.push_back(p.pid);
      }
      if (matches.empty()) {
        std::cerr << "Error: no running ceph-osd process found with OSD ID "
                  << want << " (try --list)" << std::endl;
        return 1;
      }
      if (matches.size() > 1) {
        std::cerr << "Error: OSD ID " << want << " matched multiple PIDs (";
        for (size_t i = 0; i < matches.size(); ++i)
          std::cerr << (i ? "," : "") << matches[i];
        std::cerr << "); use -p <pid> explicitly" << std::endl;
        return 1;
      }
      process_ids.insert(matches[0]);
      clog << "--id " << want << " resolved to PID " << matches[0] << endl;
    }
  }

  // Validate all process_ids if specified
  for (int pid : process_ids) {
    std::string proc_path = "/proc/" + std::to_string(pid);
    if (access(proc_path.c_str(), F_OK) != 0) {
      std::cerr << "Error: Process ID " << pid << " does not exist" << std::endl;
      return 1;
    }
  }

  struct osdtrace_bpf *skel;
  int ret = 0;
  struct ring_buffer *rb;

  std::string osd_path;

  if (!process_ids.empty()) {
    // PIDs specified - read executable path from /proc/<first_pid>/exe
    // All PIDs should be running the same ceph-osd binary
    int first_pid = *process_ids.begin();
    osd_path = get_exe_path_for_pid(first_pid);
    if (osd_path.empty()) {
      std::cerr << "Error: Could not read /proc/" << first_pid << "/exe" << std::endl;
      return 1;
    }
    clog << "Reading executable from process " << first_pid << ": " << osd_path << endl;

    // Validate that the process is actually running ceph-osd
    if (osd_path.find("ceph-osd") == std::string::npos) {
      std::cerr << "Error: Process ID " << first_pid << " is not running ceph-osd" << std::endl;
      std::cerr << "Process is running: " << osd_path << std::endl;
      return 1;
    }

    // Validate that all PIDs are running the same executable
    for (auto it = std::next(process_ids.begin()); it != process_ids.end(); ++it) {
      int pid = *it;
      std::string pid_exe = get_exe_path_for_pid(pid);
      if (pid_exe.empty()) {
        std::cerr << "Error: Could not read /proc/" << pid << "/exe" << std::endl;
        return 1;
      }
      if (pid_exe != osd_path) {
        std::cerr << "Error: Process ID " << pid << " is running a different executable" << std::endl;
        std::cerr << "Expected: " << osd_path << std::endl;
        std::cerr << "Got: " << pid_exe << std::endl;
        return 1;
      }
    }
  } else {
    // No PID specified - look for a host-side ceph-osd binary, and separately
    // discover running ceph-osd processes.  Discovery scans /proc, so it sees
    // containerized OSDs too, even though their binary is not on the host FS.
    osd_path = find_executable_path("ceph-osd");
    auto processes = discover_ceph_osd_processes();

    if (osd_path.empty()) {
      // No ceph-osd on the host filesystem.  This is the normal case when OSDs
      // run inside containers: the binary lives in the container image, so
      // there is nothing for us to read on the host without attaching to a
      // specific PID.  Instead of failing cryptically, show what we can see
      // and how to attach to it.
      if (!processes.empty()) {
        if (geteuid() != 0) {
          std::cerr << "Warning: Running without root privileges. Containerized status of OSDs owned by other users may not be accurately detected." << std::endl << std::endl;
        }
        std::cerr << "Error: no ceph-osd binary found on the host, but "
                  << processes.size() << " running ceph-osd process(es) were detected"
                  << " (your OSDs are likely containerized)." << std::endl;
        print_discovered_osds(processes);
        std::cerr << std::endl;
        std::cerr << "Use -p or --id to specify one or multiple OSD(s) to trace containerized OSDs." << std::endl;
      } else {
        std::cerr << "Error: no ceph-osd binary found on the host and no running ceph-osd processes detected." << std::endl;
        std::cerr << "If your OSDs run in containers, make sure they are running, then trace by OSD ID (--id) or PID (-p)." << std::endl;
      }
      return 1;
    }

    // Host binary found - this default mode traces the on-host ceph-osd binary,
    // so only host (non-containerized) OSD processes are relevant.  Containerized
    // OSDs can't be traced this way (use -p/--id), so exclude them from the list.
    std::vector<OsdProcessInfo> host_processes;
    for (const auto& p : processes) {
      if (!p.is_container) host_processes.push_back(p);
    }
    if (host_processes.empty()) {
      std::cout << "Warning: No active ceph-osd processes detected on the host." << std::endl;
      std::cout << "osdtrace will start tracing globally, but no events will be captured until a ceph-osd process runs." << std::endl;
    } else {
      if (geteuid() != 0) {
        std::cout << "Warning: Running without root privileges. Containerized status of OSDs owned by other users may not be accurately detected." << std::endl << std::endl;
      }
      std::cout << "Detected active ceph-osd process(es) on the host:" << std::endl;
      print_discovered_osds(host_processes);
      std::cout << std::endl;
    }
  }

  std::cout << "Tracing ceph-osd at: " << osd_path << std::endl;

  // Check if any ceph-osd processes are running with old/deleted executables.
  // Only enforced for live tracing; for JSON export we deliberately want to
  // read the *on-disk* (possibly newly-upgraded) binary so the exported
  // DWARF metadata matches the binary version recorded in the JSON, not
  // whatever stale image happens to still be mapped in the process.
  if (!export_json && check_executable_deleted(-1, "ceph-osd")) {
    std::cerr << "Warning: Found ceph-osd processes running with deleted/old executables." << std::endl;
    std::cerr << "This may indicate that ceph-osd was updated but processes haven't been restarted." << std::endl;
    std::cerr << "Consider restarting ceph-osd services for accurate tracing." << std::endl;
    return 1;
  }

  DwarfParser dwarfparser(osd_probes, probe_units);
  
  if (import_json) {
    // Import dwarf data from JSON file
    std::string version = "";

    if (skip_version_check) {
      clog << "Skipping version check as requested" << endl;
    } else {
      // Get version information for comparison
      version = get_package_version(osd_path);
      if (version != "unknown") {
        clog << "Current package version: " << version << endl;
      } else {
        clog << "Could not determine current package version for ceph-osd, exit" << endl;
        return 1;
      }
    }

    if (!dwarfparser.import_from_json(json_input_file, version)) {
      cerr << "Failed to import dwarf data from " << json_input_file << endl;
      return 1;
    }
    clog << "Successfully imported dwarf data from " << json_input_file << endl;
  } else {
    // When -j is used to export JSON, force live parsing so the output reflects
    // the installed binary (not a re-dump of the embedded data the header came
    // from). Otherwise try embedded DWARF data first, keyed by the on-disk
    // ELF build-id (arch-safe, snap-safe, custom-rebuild-safe).
    //
    // osd_path is the in-process view ("/usr/bin/ceph-osd"), which for a
    // containerized OSD doesn't exist on the host.  Reach into the target's
    // mount namespace via /proc/<pid>/root/ so the build-id read sees the
    // same binary the kernel uprobe will attach to.
    std::string osd_buildid_path = osd_path;
    if (!process_ids.empty()) {
      osd_buildid_path = "/proc/" + std::to_string(*process_ids.begin())
                         + "/root" + osd_path;
    }
    std::string osd_buildid = get_elf_build_id(osd_buildid_path);
    if (!export_json && !osd_buildid.empty() &&
        dwarfparser.import_from_embedded(
            {{get_basename(osd_path), osd_buildid}}, "osdtrace")) {
      // Detailed match info already logged inside import_from_embedded.
    } else {
      clog << "Start to parse dwarf info" << endl;
      dwarfparser.add_module(osd_path);
      dwarfparser.parse();
    }
  }

  // Export dwarf parsing results to JSON if requested
  if (export_json) {
    // Get version information from the ceph-osd binary
    std::string version = get_package_version(osd_path);
    if (version != "unknown") {
      clog << "Detected package version: " << version << endl;
    } else {
      clog << "Could not determine package version for ceph-osd, using 'unknown'" << endl;
    }
    
    dwarfparser.export_to_json(json_output_file, version);
    clog << "Dwarf parsing data exported to " << json_output_file << endl;
    return 0;
  }

  libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

  /* Set up libbpf errors and debug info callback */
  libbpf_set_print(libbpf_print_fn);

  /* Load and verify BPF application */
  clog << "Start to load uprobe" << endl;

  skel = osdtrace_bpf__open_and_load();
  if (!skel) {
    cerr << "Failed to open and load BPF skeleton" << endl;
    return 1;
  }

  // map_fd = bpf_object__find_map_fd_by_name(skel->obj, "hprobes");

  fill_map_hprobes(osd_path, dwarfparser, skel->maps.hprobes);

  clog << "BPF prog loaded" << endl;

  //Start to load the probes
  if (probe_mode == OP_SINGLE_PROBE) {
    attach_uprobes(skel, dwarfparser, osd_path, process_ids, "PrimaryLogPG::log_op_stats", 2);
  }

  if (probe_mode & OP_FULL_PROBE) {
    attach_uprobes(skel, dwarfparser, osd_path, process_ids, "OSD::dequeue_op");

    attach_uprobes(skel, dwarfparser, osd_path, process_ids, "PrimaryLogPG::execute_ctx");

    attach_uprobes(skel, dwarfparser, osd_path, process_ids, "ECBackend::submit_transaction");

    attach_uprobes(skel, dwarfparser, osd_path, process_ids, "OpRequest::mark_flag_point_string");

    attach_uprobes(skel, dwarfparser, osd_path, process_ids, "OpRequest::mark_flag_point");

    attach_uprobes(skel, dwarfparser, osd_path, process_ids, "ReplicatedBackend::generate_subop");

    attach_uprobes(skel, dwarfparser, osd_path, process_ids, "ReplicatedBackend::do_repop_reply");

    attach_uprobes(skel, dwarfparser, osd_path, process_ids, "BlueStore::queue_transactions");

    attach_uprobes(skel, dwarfparser, osd_path, process_ids, "BlueStore::_txc_calc_cost");

    attach_uprobes(skel, dwarfparser, osd_path, process_ids, "BlueStore::_txc_state_proc");

    attach_uprobes(skel, dwarfparser, osd_path, process_ids, "PrimaryLogPG::log_op_stats");

    attach_uprobes(skel, dwarfparser, osd_path, process_ids, "ReplicatedBackend::repop_commit");

    attach_uprobes(skel, dwarfparser, osd_path, process_ids, "OSD::enqueue_op");
  }

  if (probe_mode & BLUESTORE_PROBE) {
    attach_uprobes(skel, dwarfparser, osd_path, process_ids, "BlueStore::log_latency");
    attach_uprobes(skel, dwarfparser, osd_path, process_ids, "BlueStore::log_latency_fn");
  }

  bootstamp = get_bootstamp();
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

  /* we can also attach uprobe/uretprobe to any existing or future
   * processes that use the same binary executable; to do that we need
   * to specify -1 as PID, as we do here
   */
  /* Let libbpf perform auto-attach for uprobe_sub/uretprobe_sub
   * NOTICE: we provide path and symbol info in SEC for BPF programs
   */
  clog << "Unexpected line hit" << endl;
cleanup:
  clog << "Clean up the eBPF program" << endl;
  ring_buffer__free(rb);
  osdtrace_bpf__destroy(skel);
  return timeout_occurred ? -1 : -errno;
}
