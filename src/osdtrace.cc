#include <bpf/bpf.h>
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

#include "osdtrace.skel.h"

extern "C" {
#include <fcntl.h>
#include <unistd.h>
}

#include "bpf_ceph_types.h"
#include "dwarf_parser.h"

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
    {"ReplicatedBackend::repop_commit", 170}
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
    {"ReplicatedBackend::repop_commit", 17}
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

    {"log_subop_stats", 
     {{"op", "px", "reqid", "name", "_num"},
      {"op", "px", "reqid", "tid"},
      {"op", "px", "request", "data", "_len"}}},
    
    {"ECBackend::submit_transaction",
     {{"reqid", "name", "_num"}, {"reqid", "tid"}}},

    {"ReplicatedBackend::repop_commit", 
     {{"rm", "_M_ptr", "op", "px", "reqid", "name", "_num"},
      {"rm", "_M_ptr", "op", "px", "reqid", "tid"},
      {"rm", "_M_ptr", "op", "px", "request", "data", "_len"}}}
};

enum mode_e { MODE_AVG = 1, MODE_MAX, MODE_ALL };

enum mode_e mode = MODE_ALL;

enum probe_mode_e {
    OP_SINGLE_PROBE = 1,
    OP_FULL_PROBE = 2,
    BLUESTORE_PROBE = 3
};

enum probe_mode_e probe_mode = OP_SINGLE_PROBE;

static __u64 bootstamp = 0;

int threshold = 0; //in millisecond
int probe_osdid = -1;


static __u64 cnt = 0;
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

struct op_stat_s {
  __u64 recv_lat;
  __u64 dispatch_lat;
  __u64 queue_lat;
  __u64 osd_lat;
  __u64 bluestore_alloc_lat;
  __u64 bluestore_data_lat;
  __u64 bluestore_kv_lat;
  __u64 bluestore_lat;
  __u64 op_lat;
  __u64 r_cnt;
  __u64 w_cnt;
  __u64 rbytes;
  __u64 wbytes;
  __u64 max_recv_lat;
  __u64 max_dispatch_lat;
  __u64 max_queue_lat;
  __u64 max_osd_lat;
  __u64 max_bluestore_lat;
  __u64 max_op_lat;
  int aio_size;
};
int num_osd = 0;
int osds[MAX_OSD] = {0};
int pids[MAX_OSD] = {0};
struct op_stat_s op_stat[MAX_OSD];

struct timespec lasttime;
__u32 period = 0;

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
  int id = 0;
  memset(path_cmdline, 0, sizeof(path_cmdline));
  snprintf(path_cmdline, sizeof(path_cmdline), "/proc/%d/cmdline", pid);
  int fd = open(path_cmdline, O_RDONLY);
  if (read(fd, pname, 200) >= 0) {
    int start = 41;
    while (pname[start] != 0 && start < 200) {
      id *= 10;
      id += pname[start] - '0';
      ++start;
    }
  }
  close(fd);
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
  int idx = 0;
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
  for (int i = 0; i < op.delayed_cnt; ++i) {
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
  for (int i = 0; i < op.delayed_cnt; ++i) {
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
  for (int i = 0; i < op.delayed_cnt; ++i) {
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

osd_op_t generate_op(op_v *val) {
  osd_op_t op;
  memset(&op, 0, sizeof(osd_op_t));

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

void handle_avg(struct op_v *val, int osd_id) {

  __u64 recv_stamp = val->recv_stamp;
  if (val->throttle_stamp < val->recv_stamp) { 
      //Due to recv_stamp bug https://tracker.ceph.com/issues/52739
      //Releases older than 16.2.7, the recv_stamp is not accurate at all
      //Hence we'll use the throttle_stamp as the recv_stamp, which will only lose 1-3 microseconds
      recv_stamp = val->throttle_stamp;
  }

  op_stat[osd_id].recv_lat += (val->recv_complete_stamp - recv_stamp);
  op_stat[osd_id].max_recv_lat =
      MAX(op_stat[osd_id].max_recv_lat,
          (val->recv_complete_stamp - recv_stamp));
  op_stat[osd_id].dispatch_lat +=
      (val->enqueue_stamp - (val->recv_complete_stamp - bootstamp));
  op_stat[osd_id].max_dispatch_lat =
      MAX(op_stat[osd_id].max_dispatch_lat,
          (val->enqueue_stamp - (val->recv_complete_stamp - bootstamp)));
  op_stat[osd_id].queue_lat += (val->dequeue_stamp - val->enqueue_stamp);
  op_stat[osd_id].max_queue_lat = MAX(
      op_stat[osd_id].max_queue_lat, (val->dequeue_stamp - val->enqueue_stamp));
  op_stat[osd_id].osd_lat +=
      (val->queue_transaction_stamp - val->dequeue_stamp);
  op_stat[osd_id].max_osd_lat =
      MAX(op_stat[osd_id].max_osd_lat,
          (val->queue_transaction_stamp - val->dequeue_stamp));
  op_stat[osd_id].bluestore_alloc_lat +=
      (val->aio_done_stamp - val->do_write_stamp);
  op_stat[osd_id].bluestore_data_lat +=
      (val->aio_done_stamp - val->aio_submit_stamp);
  op_stat[osd_id].bluestore_kv_lat +=
      (val->kv_committed_stamp - val->kv_submit_stamp);
  op_stat[osd_id].bluestore_lat +=
      (val->kv_committed_stamp - val->queue_transaction_stamp);
  op_stat[osd_id].max_bluestore_lat =
      MAX(op_stat[osd_id].max_bluestore_lat,
          (val->kv_committed_stamp - val->queue_transaction_stamp));
  op_stat[osd_id].op_lat += (val->reply_stamp - (recv_stamp - bootstamp));
  op_stat[osd_id].max_op_lat =
      MAX(op_stat[osd_id].max_op_lat,
          (val->reply_stamp - (recv_stamp - bootstamp)));
  op_stat[osd_id].r_cnt += (val->rb ? 1 : 0);
  op_stat[osd_id].w_cnt += (val->wb ? 1 : 0);
  op_stat[osd_id].rbytes += val->rb;
  op_stat[osd_id].wbytes += val->wb;

  // printf("Number is %lld Client.%lld tid %lld recv_stamp %lld
  // recv_complete_stamp %lld dispatch_stamp %lld enqueue_stamp %lld
  // dequeue_stamp %lld execute_ctx_stamp %lld submit_transaction %lld
  // do_write_stamp %lld wctx_finish_stamp %lld data_submit_stamp %lld
  // data_committed_stamp %lld kv_submit_stamp %lld kv_committed_stamp %lld
  // reply_stamp %lld write_bytes %lld read_bytes %lld\n",cnt, val->owner,
  // val->tid, val->recv_stamp-bootstamp, val->recv_complete_stamp-bootstamp,
  // val->dispatch_stamp-bootstamp, val->enqueue_stamp, val->dequeue_stamp,
  // val->execute_ctx_stamp, val->submit_transaction_stamp, val->do_write_stamp,
  // val->wctx_finish_stamp, val->data_submit_stamp, val->data_committed_stamp,
  // val->kv_submit_stamp, val->kv_committed_stamp, val->reply_stamp, val->wb,
  // val->rb);
  struct timespec now;
  clock_gettime(CLOCK_BOOTTIME, &now);
  __u64 interval = timespec_sub_ms(&now, &lasttime);
  if (interval >= period * 1000) {
    int interval_s = MAX(1, interval / 1000);
    if (period > 0)
      printf(
          "OSD  r/s    w/s    rkB/s    wkB/s     rcv_lat     disp_lat      "
          "qu_lat      osd_lat   bs_alloc_lat    bs_data_lat      bs_kv_lat    "
          "    op_lat\n");
    for (int i = 0; i < num_osd; ++i) {
      osd_id = osds[i];
      cnt = op_stat[osd_id].w_cnt + op_stat[osd_id].r_cnt;
      if (cnt == 0 && period == 0) continue;
      cnt = MAX(cnt, 1);
      printf(
          "%3d "
          "%4lld%7lld%9lld%9lld%12.3f%13.3f%12.3f%13.3f%15.3f%15.3f%15.3f%14."
          "3f \n",
          osd_id, op_stat[osd_id].r_cnt / interval_s,
          op_stat[osd_id].w_cnt / interval_s,
          op_stat[osd_id].rbytes / interval_s / 1024,
          op_stat[osd_id].wbytes / interval_s / 1024,
          mode == MODE_AVG ? (op_stat[osd_id].recv_lat / cnt / 1000.0)
                           : (op_stat[osd_id].max_recv_lat / 1000.0),
          mode == MODE_AVG ? (op_stat[osd_id].dispatch_lat / cnt / 1000.0)
                           : (op_stat[osd_id].max_dispatch_lat / 1000.0),
          mode == MODE_AVG ? (op_stat[osd_id].queue_lat / cnt / 1000.0)
                           : (op_stat[osd_id].max_queue_lat / 1000.0),
          mode == MODE_AVG ? (op_stat[osd_id].osd_lat / cnt / 1000.0)
                           : (op_stat[osd_id].max_osd_lat / 1000.0),
          mode == MODE_AVG
              ? (op_stat[osd_id].bluestore_alloc_lat / cnt / 1000.0)
              : 0,
          mode == MODE_AVG ? (op_stat[osd_id].bluestore_data_lat / cnt / 1000.0)
                           : 0,
          mode == MODE_AVG ? (op_stat[osd_id].bluestore_kv_lat / cnt / 1000.0)
                           : 0,
          // mode == MODE_AVG ? (op_stat[osd_id].bluestore_lat/cnt / 1000.0) :
          // (op_stat[osd_id].max_bluestore_lat / 1000.0),
          mode == MODE_AVG ? (op_stat[osd_id].op_lat / cnt / 1000.0)
                           : (op_stat[osd_id].max_op_lat / 1000.0));
      memset(&op_stat[osd_id], 0, sizeof(op_stat[osd_id]));
    }
    if (period > 0) printf("\n\n");
    lasttime = now;
  }

  // printf("Number is %lld Client.%lld tid %lld recv_stamp %lld
  // recv_complete_stamp %lld dispatch_stamp %lld enqueue_stamp %lld
  // dequeue_stamp %lld execute_ctx_stamp %lld submit_transaction %lld
  // reply_stamp %lld write_bytes %lld read_bytes %lld\n",cnt, val->owner,
  // val->tid, val->recv_stamp-bootstamp, val->recv_complete_stamp-bootstamp,
  // val->dispatch_stamp-bootstamp, val->enqueue_stamp, val->dequeue_stamp,
  // val->execute_ctx_stamp, val->submit_transaction_stamp, val->reply_stamp,
  // val->wb, val->rb); printf("The current number is %lld Client.%lld tid %lld
  // enqueue_stamp %lld dequeue_stamp %lld\n",cnt, val->owner, val->tid,
  // val->enqueue_stamp, val->dequeue_stamp);
}

void handle_bluestore(struct bluestore_lat_v *val, int osd_id) {
    switch(val->idx) {
      case l_bluestore_kv_flush_lat:
	  printf("kv_flush_lat %lld ", val->lat/1000);
	  break;
      case l_bluestore_kv_commit_lat:
	  printf("kv_commit_lat %lld ", val->lat/1000);
	  break;
      case l_bluestore_kv_sync_lat:
	  printf("kv_sync_lat is %lld\n", val->lat/1000);
	  break;
      default:
	  //printf("Bluestore lat Not captured yet: %lld\n", val->lat);
	  break;
    }
    //printf("idx is %d, lat is %lld\n", val->idx, val->lat);
}

static int handle_event(void *ctx, void *data, size_t size) {
  int osd_id = -1;
  int pid = 0;
  if (probe_mode == OP_SINGLE_PROBE) {
    struct op_v *val = (struct op_v *)data;
    pid = val->pid;
    osd_id = osd_pid_to_id(pid);
    if (probe_osdid == -1 || probe_osdid == osd_id)
      handle_single(val, osd_id);
  } else if (probe_mode == OP_FULL_PROBE){
    struct op_v *val = (struct op_v *)data;
    pid = val->pid;
    osd_id = osd_pid_to_id(pid);
    if (probe_osdid == -1 || probe_osdid == osd_id)
    {
      if (mode == MODE_AVG) {
	clog << "avg mode needs to be refined" << endl;
        //handle_avg(val, osd_id);
      } else if (mode == MODE_ALL){
        handle_full(val, osd_id);
      }
    }
    //print_full(val, osd_id);
  } else if (probe_mode == BLUESTORE_PROBE) {
    struct bluestore_lat_v *val = (struct bluestore_lat_v *) data;
    pid = val->pid;
    osd_id = osd_pid_to_id(pid);
    if (probe_osdid == -1 || probe_osdid == osd_id)
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

int process_id = -1;  // Default to -1
int parse_args(int argc, char **argv) {
  char opt;
  while ((opt = getopt(argc, argv, ":d:m:t:o:xbj:i:p:")) != -1) {
    switch (opt) {
      case 'd':
        period = optarg[0] - '0';
        break;
      case 'm':
        if (0 == strcmp(optarg, "avg")) {
          mode = MODE_AVG;
        } else if (0 == strcmp(optarg, "max")) {
          mode = MODE_MAX;
        } else {
          clog << "Unknown mode" << endl;
          return -1;
        }
        break;
      case 't':
        threshold = stoi(optarg);
        break;
      case 'x':
        probe_mode = OP_FULL_PROBE;
	break;
      case 'b':
        probe_mode = BLUESTORE_PROBE;
	break;
      case 'o':
	probe_osdid = stoi(optarg);
	break;
      case 'j':
        //export_json = true;
        //json_output_file = optarg;
        break;
      case 'i':
        //import_json = true;
        //json_input_file = optarg;
        break;
      case 'p':
        process_id = stoi(optarg);
        break;
      case '?':
        clog << "Unknown option: " << optopt << endl;
        return -1;
      case ':':
        clog << "Missing arg for " << optopt << endl;
        return -1;
    }
  }
  return 0;
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
      bpf_map_update_elem(bpf_map__fd(hprobes), &key_idx, &vfk, 0);
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

  std::string pid_path = path;
  if (process_id != -1) {
    pid_path = "/proc/" + std::to_string(process_id) + "/root/" + path;
  }

  auto &func2pc = dp.mod_func2pc[path];
  size_t func_addr = func2pc[funcname];
  if (v > 0)
      funcname = funcname + "_v" + std::to_string(v); 
  int pid = func_progid[funcname];
  struct bpf_link *ulink = bpf_program__attach_uprobe(
      *skel->skeleton->progs[pid].prog, 
      false /* not uretprobe */,
      -1,  // Pass the process_id parameter here
      pid_path.c_str(), func_addr);
  if (!ulink) {
    cerr << "Failed to attach uprobe to " << funcname << endl;
    return -errno;
  }

  clog << "uprobe " << funcname <<  " attached" << endl;
  return 0;
}

int attach_retuprobe(struct osdtrace_bpf *skel,
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

int main(int argc, char **argv) {
  signal(SIGINT, signal_handler); 

  if (parse_args(argc, argv) < 0) return 0;

  struct osdtrace_bpf *skel;
  int ret = 0;
  struct ring_buffer *rb;

  clog << "Start to parse ceph dwarf info" << endl;

  std::string osd_path = "/usr/bin/ceph-osd";
  DwarfParser dwarfparser(osd_probes, probe_units);
  
  // Normal dwarf parsing path
  dwarfparser.add_module(osd_path);
  dwarfparser.parse();

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
    attach_uprobe(skel, dwarfparser, osd_path, process_id, "PrimaryLogPG::log_op_stats", 2);
  } else if (probe_mode == OP_FULL_PROBE) {
    attach_uprobe(skel, dwarfparser, osd_path, process_id, "OSD::dequeue_op");

    attach_uprobe(skel, dwarfparser, osd_path, process_id, "PrimaryLogPG::execute_ctx");
    
    attach_uprobe(skel, dwarfparser, osd_path, process_id, "ECBackend::submit_transaction");

    attach_uprobe(skel, dwarfparser, osd_path, process_id, "OpRequest::mark_flag_point_string");

    attach_uprobe(skel, dwarfparser, osd_path, process_id, "ReplicatedBackend::generate_subop");

    attach_uprobe(skel, dwarfparser, osd_path, process_id, "ReplicatedBackend::do_repop_reply");

    attach_uprobe(skel, dwarfparser, osd_path, process_id, "BlueStore::queue_transactions");

    attach_uprobe(skel, dwarfparser, osd_path, process_id, "BlueStore::_txc_calc_cost");

    attach_uprobe(skel, dwarfparser, osd_path, process_id, "BlueStore::_txc_state_proc");

    attach_uprobe(skel, dwarfparser, osd_path, process_id, "PrimaryLogPG::log_op_stats");

    attach_uprobe(skel, dwarfparser, osd_path, process_id, "ReplicatedBackend::repop_commit");
    
    attach_uprobe(skel, dwarfparser, osd_path, process_id, "OSD::enqueue_op");
  } else if (probe_mode == BLUESTORE_PROBE) {
    attach_uprobe(skel, dwarfparser, osd_path, process_id, "BlueStore::log_latency");
  }

  bootstamp = get_bootstamp();
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
  return -errno;
}
