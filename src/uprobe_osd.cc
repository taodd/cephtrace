#include <errno.h>
#include <stdio.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <time.h>
#include <getopt.h>
#include "uprobe_osd.skel.h"
#include <vector>
#include <map>
#include <unordered_map>
#include <string>
#include <iostream>
#include <cassert>
#include <cstring>
#include <ctime>
extern "C" {
#include <unistd.h>
#include <fcntl.h>
#include <elfutils/libdwfl.h>
#include <elfutils/libdw.h>
#include <dwarf.h>
#include <elf.h>
}
#include "bpf_osd_types.h"

#define MAX_CNT 100000ll
#define MAX_OSD 4000
#define PATH_MAX 4096

#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))


typedef std::map<std::string, std::vector<std::vector<std::string>> > probes_t;
typedef std::map<std::string, int> func_id_t;

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
    {"PrimaryLogPG::log_op_stats", 90} 
};

std::vector<std::string> probe_units = {"OSD.cc", "BlueStore.cc", "PrimaryLogPG.cc", "ReplicatedBackend.cc"};

probes_t probes = {

    { "OSD::enqueue_op", { 
			     {"op", "px", "request", "header", "type"},
			     {"op", "px", "reqid", "name", "_num"}, 
			     {"op", "px", "reqid", "tid"},
			     {"op", "px", "request", "recv_stamp"},
			     {"op", "px", "request", "recv_complete_stamp"},
			     {"op", "px", "request", "dispatch_stamp"}
			 } 
    }, 
    
    {"OSD::dequeue_op", {
			    {"op", "px", "request", "header", "type"},
			    {"op", "px", "reqid", "name", "_num"}, 
			    {"op", "px", "reqid", "tid"}
			}
    },

    { "PrimaryLogPG::execute_ctx", { 
				       {"ctx", "reqid", "name", "_num"}, 
				       {"ctx", "reqid", "tid"}  
				   } 
    },

    { "ReplicatedBackend::submit_transaction", { 
						   {"reqid", "name", "_num"}, 
						   {"reqid", "tid"} 
					       } 
    }, 

    {
	"BlueStore::queue_transactions", {}
    },

    { "BlueStore::_do_write", {
			       //{"txc"},
			       //{"offset"},
			       //{"length"}
   			      }
    },

    { "BlueStore::_wctx_finish", {
				     //{"txc"}
				 }
    },

    {
	"BlueStore::_txc_state_proc", {
	                                {"txc", "state"}
	                              }
    },
    
    {
	"BlueStore::_txc_apply_kv", {
	                                {"txc", "state"}
	                            }
    },


    { "PrimaryLogPG::log_op_stats", { 
					{"op", "reqid", "name", "_num"}, 
					{"op", "reqid", "tid"}, 
					{"inb"}, 
					{"outb"} 
				    } 
    }
    
};

std::map<std::string, std::vector<VarField>> func2vf;
std::map<std::string, Dwarf_Addr> func2pc;


typedef std::unordered_map<std::string, Dwarf_Die> cu_type_cache_t;
typedef std::unordered_map<void*, cu_type_cache_t> mod_cu_type_cache_t;

mod_cu_type_cache_t global_type_cache;

enum mode_e {
    MODE_AVG=1, MODE_MAX
};

enum mode_e mode = MODE_AVG;

static __u64 bootstamp = 0;

static __u64 cnt = 0;
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG)
	return 0;
    return vfprintf(stderr, format, args);
}

#define DEBUG printf

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
};
int num_osd = 0;
int osds[MAX_OSD] = {0};
int pids[MAX_OSD] = {0};
struct op_stat_s op_stat[MAX_OSD];

struct timespec lasttime;
__u32 period = 0; 


void print_die(Dwarf_Die *die) {
    //printf("DIE information:\n");
    //printf("  Offset: %llu\n", static_cast<unsigned long long>(dwarf_dieoffset(die)));
    //printf("  Tag: %s\n", dwarf_tag_string(dwarf_tag(die)));
    //printf("  Name: %s\n", dwarf_diename(die));

    /*TODO print attribute
    Dwarf_Attribute attr;
    Dwarf_Attribute *attr_result = nullptr;
    while ((attr_result = dwarf_attr_integrate(die, attr_result ? attr.code + 1 : 0, &attr)) != nullptr) {
        const char *attr_name = dwarf_attr_string(attr.code);
        printf("  Attribute: %s\n", attr_name);

        Dwarf_Word value;
        if (dwarf_formudata(&attr, &value) == 0) {
            printf("    Value: %llu\n", static_cast<unsigned long long>(value));
        } else {
            const char *str_value = dwarf_formstring(&attr);
            if (str_value) {
                printf("    Value: %s\n", str_value);
            }
        }
    }*/
}

int exists(int id)
{
    for (int i = 0; i < num_osd; ++i)
    {
       if (osds[i] == id)
         return 1;
    }
    return 0;
}

int osd_pid_to_id(__u32 pid) 
{
    for (int i = 0; i < num_osd; ++i) {
       if (pids[i] == (int)pid) {
          return osds[i];
       }
    } 
    //First time, read from /proc/<pid>/cmdline
    char path_cmdline[50];
    char pname[200];
    int id = 0;
    memset(path_cmdline, 0, sizeof(path_cmdline));
    snprintf(path_cmdline, sizeof(path_cmdline), "/proc/%d/cmdline", pid);
    int fd = open(path_cmdline, O_RDONLY);
    if(read(fd, pname, 200) >= 0) {
       id = pname[41] - '0';
    }
    close(fd);
    //DEBUG("pid %d, osd_id %d\n", pid, id);
    return id;
}

__u64 to_ns(struct timespec *ts) 
{
   return ts->tv_nsec + (ts->tv_sec * 1000000000ull);
}

__u64 to_us(struct timespec *ts) 
{
   return (ts->tv_nsec / 1000) + (ts->tv_sec * 1000000ull);
}

__u64 to_ms(struct timespec *ts)
{
   return (ts->tv_nsec / 1000000) + (ts->tv_sec * 1000);
}

void timespec_diff(struct timespec *start, struct timespec *stop,
                   struct timespec *result)
{
    if ((stop->tv_nsec - start->tv_nsec) < 0) {
        result->tv_sec = stop->tv_sec - start->tv_sec - 1;
        result->tv_nsec = stop->tv_nsec - start->tv_nsec + 1000000000;
    } else {
        result->tv_sec = stop->tv_sec - start->tv_sec;
        result->tv_nsec = stop->tv_nsec - start->tv_nsec;
    }

    return;
}

__u64 timespec_sub_ms(struct timespec *a, struct timespec *b)
{
   struct timespec c;
   timespec_diff(b, a, &c);
   return to_ms(&c);
}

__u64 get_bootstamp() 
{
	struct timespec realtime, boottime, prevtime;
	clock_gettime( CLOCK_REALTIME, &realtime );
	clock_gettime( CLOCK_BOOTTIME, &boottime );
	timespec_diff(&boottime, &realtime, &prevtime);

	return (prevtime.tv_sec * 1000000000ull) + prevtime.tv_nsec;
} 

static int handle_event(void *ctx, void *data, size_t size)
{
    struct op_v *val = (struct op_v *)data;

    if (val->wb == 0) { // TODO handling read
       return 0;
    }

    int osd_id = osd_pid_to_id(val->pid);
    if (!exists(osd_id)){
       osds[num_osd] = osd_id;
       pids[num_osd++] = val->pid;
    }
    op_stat[osd_id].recv_lat += (val->recv_complete_stamp - val->recv_stamp);
    op_stat[osd_id].max_recv_lat = MAX(op_stat[osd_id].max_recv_lat, (val->recv_complete_stamp - val->recv_stamp));
    op_stat[osd_id].dispatch_lat += (val->enqueue_stamp - (val->recv_complete_stamp - bootstamp) );
    op_stat[osd_id].max_dispatch_lat = MAX(op_stat[osd_id].max_dispatch_lat, (val->enqueue_stamp - (val->recv_complete_stamp - bootstamp) ));
    op_stat[osd_id].queue_lat += (val->dequeue_stamp - val->enqueue_stamp);
    op_stat[osd_id].max_queue_lat = MAX(op_stat[osd_id].max_queue_lat, (val->dequeue_stamp - val->enqueue_stamp));
    op_stat[osd_id].osd_lat += (val->submit_transaction_stamp - val->dequeue_stamp);
    op_stat[osd_id].max_osd_lat = MAX(op_stat[osd_id].max_osd_lat, (val->submit_transaction_stamp - val->dequeue_stamp));
    op_stat[osd_id].bluestore_alloc_lat += (val->data_submit_stamp - val->do_write_stamp);
    op_stat[osd_id].bluestore_data_lat += (val->data_committed_stamp - val->data_submit_stamp);
    op_stat[osd_id].bluestore_kv_lat += (val->kv_committed_stamp - val->kv_submit_stamp);
    op_stat[osd_id].bluestore_lat += (val->reply_stamp - val->submit_transaction_stamp);
    op_stat[osd_id].max_bluestore_lat = MAX(op_stat[osd_id].max_bluestore_lat, (val->reply_stamp - val->submit_transaction_stamp));
    op_stat[osd_id].op_lat += (val->reply_stamp - (val->recv_stamp - bootstamp));
    op_stat[osd_id].max_op_lat = MAX(op_stat[osd_id].max_op_lat,  (val->reply_stamp - (val->recv_stamp - bootstamp)));
    op_stat[osd_id].r_cnt += (val->rb ? 1 : 0);
    op_stat[osd_id].w_cnt += (val->wb ? 1 : 0);
    op_stat[osd_id].rbytes += val->rb;
    op_stat[osd_id].wbytes += val->wb;
    //printf("Number is %lld Client.%lld tid %lld recv_stamp %lld recv_complete_stamp %lld dispatch_stamp %lld enqueue_stamp %lld dequeue_stamp %lld execute_ctx_stamp %lld submit_transaction %lld do_write_stamp %lld wctx_finish_stamp %lld data_submit_stamp %lld data_committed_stamp %lld kv_submit_stamp %lld kv_committed_stamp %lld reply_stamp %lld write_bytes %lld read_bytes %lld\n",cnt, val->owner, val->tid, val->recv_stamp-bootstamp, val->recv_complete_stamp-bootstamp, val->dispatch_stamp-bootstamp, val->enqueue_stamp, val->dequeue_stamp, val->execute_ctx_stamp, val->submit_transaction_stamp, val->do_write_stamp, val->wctx_finish_stamp, val->data_submit_stamp, val->data_committed_stamp, val->kv_submit_stamp, val->kv_committed_stamp, val->reply_stamp, val->wb, val->rb);
    struct timespec now;
    clock_gettime(CLOCK_BOOTTIME, &now);
    __u64 interval = timespec_sub_ms(&now, &lasttime);    
    if(interval >= period * 1000) {
       int interval_s = MAX(1, interval / 1000);
       if (period > 0) 
	       printf("OSD  r/s    w/s    rkB/s    wkB/s     rcv_lat     disp_lat      qu_lat      osd_lat   bs_alloc_lat    bs_data_lat      bs_kv_lat        op_lat\n");
       for (int i = 0; i < num_osd; ++i) {
         osd_id = osds[i];
         cnt = op_stat[osd_id].w_cnt + op_stat[osd_id].r_cnt;
	 if(cnt == 0 && period == 0) 
	    continue;
	 cnt = MAX(cnt, 1);
         printf("%3d %4lld%7lld%9lld%9lld%12.3f%13.3f%12.3f%13.3f%15.3f%15.3f%15.3f%14.3f \n", 
			osd_id,
                        op_stat[osd_id].r_cnt/interval_s, op_stat[osd_id].w_cnt/interval_s, 
                        op_stat[osd_id].rbytes/interval_s/1024, op_stat[osd_id].wbytes/interval_s/1024, 
                        mode == MODE_AVG ? (op_stat[osd_id].recv_lat/cnt / 1000.0) : (op_stat[osd_id].max_recv_lat / 1000.0), 
			mode == MODE_AVG ? (op_stat[osd_id].dispatch_lat/cnt / 1000.0) : (op_stat[osd_id].max_dispatch_lat / 1000.0), 
                        mode == MODE_AVG ? (op_stat[osd_id].queue_lat/cnt / 1000.0) : (op_stat[osd_id].max_queue_lat / 1000.0), 
			mode == MODE_AVG ? (op_stat[osd_id].osd_lat/cnt / 1000.0) : (op_stat[osd_id].max_osd_lat / 1000.0),
			mode == MODE_AVG ? (op_stat[osd_id].bluestore_alloc_lat/cnt / 1000.0) : 0,
			mode == MODE_AVG ? (op_stat[osd_id].bluestore_data_lat/cnt / 1000.0) : 0,
			mode == MODE_AVG ? (op_stat[osd_id].bluestore_kv_lat/cnt / 1000.0) : 0,
                        //mode == MODE_AVG ? (op_stat[osd_id].bluestore_lat/cnt / 1000.0) : (op_stat[osd_id].max_bluestore_lat / 1000.0),
			mode == MODE_AVG ? (op_stat[osd_id].op_lat/cnt / 1000.0) : (op_stat[osd_id].max_op_lat / 1000.0) );
         memset(&op_stat[osd_id], 0, sizeof(op_stat[osd_id]));
       }
       if (period > 0)
          printf("\n\n");
       lasttime = now;
    }
    
    //printf("Number is %lld Client.%lld tid %lld recv_stamp %lld recv_complete_stamp %lld dispatch_stamp %lld enqueue_stamp %lld dequeue_stamp %lld execute_ctx_stamp %lld submit_transaction %lld reply_stamp %lld write_bytes %lld read_bytes %lld\n",cnt, val->owner, val->tid, val->recv_stamp-bootstamp, val->recv_complete_stamp-bootstamp, val->dispatch_stamp-bootstamp, val->enqueue_stamp, val->dequeue_stamp, val->execute_ctx_stamp, val->submit_transaction_stamp, val->reply_stamp, val->wb, val->rb);
    //printf("The current number is %lld Client.%lld tid %lld enqueue_stamp %lld dequeue_stamp %lld\n",cnt, val->owner, val->tid, val->enqueue_stamp, val->dequeue_stamp);
    
    return 0;
}

/*
static void handle_lost_event(void *ctx, int cpu, __u64 lost_cnt)
{
	printf("lost %llu events on cpu %d\n", lost_cnt, cpu);
}
*/

int parse_args(int argc, char **argv)
{
    char opt;
    while ((opt = getopt(argc, argv, ":d:m:")) != -1) 
    {
	switch (opt) 
        {
	    case 'd':
		period = optarg[0] - '0';
                break;
            case 'm':
		if(0 == strcmp(optarg, "avg")) {
		    mode = MODE_AVG;
		} else if(0 == strcmp(optarg, "max")) {
		    mode = MODE_MAX;
		} else {
		    printf("Unknown mode\n");
		    return -1;
		}
                break;
	    case '?':
		printf("Unknown option: %c \n ", optopt);
	        return -1;
	    case ':':
		printf("Missing arg for %c \n", optopt);
	        return -1;
        }
    }
    return 0;
}

void fill_map_hprobes(struct bpf_map *hprobes)
{
    for(auto x : func2vf)
    {
	
	std::string funcname = x.first;
        int key_idx = func_id[funcname];
	for (auto vf : x.second) 
	{
	   struct VarField_Kernel vfk;
	   vfk.varloc = vf.varloc;
	   printf("fill_map_hprobes: function %s var location : register %d, offset %d, stack %d\n", funcname.c_str(), vfk.varloc.reg, vfk.varloc.offset, vfk.varloc.stack);
	   vfk.size = vf.fields.size();
	   for (int i = 0; i < vfk.size; ++i) {
	       vfk.fields[i] = vf.fields[i];
	   }
	   bpf_map__update_elem(hprobes, &key_idx, sizeof(key_idx), &vfk, sizeof(vfk), 0);
	   ++key_idx;
	}
    }
}
    
int main(int argc, char **argv)
{
    
        if(parse_args(argc, argv) < 0)
	    return 0;

        struct uprobe_osd_bpf *skel;
        //long uprobe_offset;
        int ret=0;
	struct ring_buffer *rb;

	DEBUG("Start to parse ceph dwarf info\n");

	//parse_ceph_dwarf("/usr/bin/ceph-osd");
	parse_ceph_dwarf("/home/taodd/Git/ceph/build/bin/ceph-osd");

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Load and verify BPF application */
	DEBUG("Start to load uprobe\n");

	skel = uprobe_osd_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	//map_fd = bpf_object__find_map_fd_by_name(skel->obj, "hprobes");

	fill_map_hprobes(skel->maps.hprobes);

	/* Attach tracepoint handler */
	DEBUG("BPF prog loaded\n");

        size_t enqueue_op_addr = func2pc["OSD::enqueue_op"];	
	struct bpf_link *ulink = bpf_program__attach_uprobe(skel->progs.uprobe_enqueue_op,
							    false /* not uretprobe */,
							    //176928 /* self pid */,
							    -1,
							    //"/usr/bin/ceph-osd",
							    "/home/taodd/Git/ceph/build/bin/ceph-osd",
							    enqueue_op_addr);
	if (!ulink) {
		DEBUG("Failed to attach uprobe to uprobe_dequeue_op\n");
		return -errno;
	}
	
	DEBUG("uprobe_enqueue_op attached\n");	

	__u64 dequeue_op_addr = func2pc["OSD::dequeue_op"];
	ulink = bpf_program__attach_uprobe(skel->progs.uprobe_dequeue_op,
							    false ,
							    -1,
							   //176928,
							    //"/usr/bin/ceph-osd",
							    "/home/taodd/Git/ceph/build/bin/ceph-osd",
							    dequeue_op_addr);
	
	DEBUG("uprobe_dequeue_op attached\n");	

	if (!ulink) {
		DEBUG("Failed to attach uprobe to uprobe_dequeue_op\n");
		return -errno;
	}

	__u64 execute_ctx_addr = func2pc["PrimaryLogPG::execute_ctx"];
	ulink = bpf_program__attach_uprobe(skel->progs.uprobe_execute_ctx,
							    false ,
							    -1,
							    //176928,
							    //"/usr/bin/ceph-osd",
							    "/home/taodd/Git/ceph/build/bin/ceph-osd",
							    execute_ctx_addr);
	
	DEBUG("uprobe_execute_ctx attached\n");	

	if (!ulink) {
		DEBUG("Failed to attach uprobe to uprobe_execute_ctx\n");
		return -errno;
	}
	
	__u64 submit_transaction_addr = func2pc["ReplicatedBackend::submit_transaction"];
	ulink = bpf_program__attach_uprobe(skel->progs.uprobe_submit_transaction,
							    false,
							    //176928,
							    -1,
							    //"/usr/bin/ceph-osd",
							    "/home/taodd/Git/ceph/build/bin/ceph-osd",
							    submit_transaction_addr);
	
	if (!ulink) {
		DEBUG("Failed to attach uprobe to uprobe_submit_transaction\n");
		return -errno;
	}
	DEBUG("uprobe_submit_transaction attached\n");	
	
	__u64 log_op_stats_addr = func2pc["PrimaryLogPG::log_op_stats"];
	ulink = bpf_program__attach_uprobe(skel->progs.uprobe_log_op_stats,
							    false ,
							    //176928 ,
							    -1,
							    //"/usr/bin/ceph-osd",
							    "/home/taodd/Git/ceph/build/bin/ceph-osd",
							    log_op_stats_addr);
	
	if (!ulink) {
		DEBUG("Failed to attach uprobe to log_op_stats\n");
		return -errno;
	}

	DEBUG("uprobe_log_op_stats attached\n");	


	__u64 do_write_addr = func2pc["BlueStore::_do_write"];
	ulink = bpf_program__attach_uprobe(skel->progs.uprobe_do_write,
							    false ,
							    //176928 ,
							    -1,
							    //"/usr/bin/ceph-osd",
							    "/home/taodd/Git/ceph/build/bin/ceph-osd",
							    do_write_addr);
	
	if (!ulink) {
		DEBUG("Failed to attach uprobe to do_write_addr\n");
		return -errno;
	}
	DEBUG("uprobe_do_write attached\n");	

	__u64 wctx_finish_addr = func2pc["BlueStore::_wctx_finish"];
	ulink = bpf_program__attach_uprobe(skel->progs.uprobe_wctx_finish,
							    false ,
							    //176928 ,
							    -1,
							    //"/usr/bin/ceph-osd",
							    "/home/taodd/Git/ceph/build/bin/ceph-osd",
							    wctx_finish_addr);
	
	if (!ulink) {
		DEBUG("Failed to attach uprobe to wctx_finish_addr\n");
		return -errno;
	}
	DEBUG("uprobe_wctx_finish attached\n");	

	__u64 txc_state_proc_addr = func2pc["BlueStore::_txc_state_proc"];
	ulink = bpf_program__attach_uprobe(skel->progs.uprobe_txc_state_proc,
							    false ,
							    //176928 ,
							    -1,
							    //"/usr/bin/ceph-osd",
							    "/home/taodd/Git/ceph/build/bin/ceph-osd",
							    txc_state_proc_addr);
	
	if (!ulink) {
		DEBUG("Failed to attach uprobe to txc_state_proc_addr\n");
		return -errno;
	}
	DEBUG("uprobe_txc_state_proc attached\n");	

	__u64 txc_apply_kv_addr = func2pc["BlueStore::_txc_apply_kv"];
	ulink = bpf_program__attach_uprobe(skel->progs.uprobe_txc_apply_kv,
							    false ,
							    //176928 ,
							    -1,
							    //"/usr/bin/ceph-osd",
							    "/home/taodd/Git/ceph/build/bin/ceph-osd",
							    txc_apply_kv_addr);
	
	if (!ulink) {
		DEBUG("Failed to attach uprobe to txc_apply_kv\n");
		return -errno;
	}
	DEBUG("uprobe_txc_apply_kv attached\n");	

	bootstamp = get_bootstamp();
	DEBUG("New a ring buffer\n");
	
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if(!rb) {
		printf("failed to setup ring_buffer\n");
		goto cleanup;
	}

	DEBUG("Started to poll from ring buffer\n");

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
	DEBUG("Unexpected line hit\n");
        sleep(600);
cleanup:
	printf("Clean up the eBPF program\n");
	ring_buffer__free(rb);
	uprobe_osd_bpf__destroy(skel);
	return -errno;
}
