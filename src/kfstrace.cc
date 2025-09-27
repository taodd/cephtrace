// Kernel-level Ceph client tracing
// Traces requests from Ceph kernel clients to OSDs using kprobes

#include <bpf/libbpf.h>
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <sys/resource.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <linux/types.h>

#include <cassert>
#include <cstring>
#include <ctime>
#include <iostream>
#include <map>
#include <string>
#include <sstream>
#include <vector>

#include "kfstrace.skel.h"
#include "bpf_ceph_types.h"

#define CEPH_PG_MAX_SIZE 8
#define CEPH_OID_INLINE_LEN 32
#define CEPH_OSD_MAX_OPS 3

// MDS tracing constants (must match eBPF definitions)
#define CEPH_MDS_OP_NAME_MAX 32
#define CEPH_MDS_PATH_MAX 128


struct kernel_trace_event {
    __u64 tid;
    __u64 client_id;
    __u64 start_time;
    __u64 end_time;
    __u64 latency_us;
    __u32 primary_osd;
    __u32 acting_osds[CEPH_PG_MAX_SIZE];
    __u32 acting_size;
    __u32 pid;
    __u32 attempts;         // Number of send attempts
    char object_name[CEPH_OID_INLINE_LEN];
    __u32 object_name_len;
    __u8 is_read;
    __u8 is_write;
    __u64 pool_id;
    __u32 pg_id;
    __u16 ops[CEPH_OSD_MAX_OPS];
    __u8 ops_size;
    __u64 offset;
    __u64 length;
    cls_op_t cls_ops[CEPH_OSD_MAX_OPS];
} __attribute__((packed));

// MDS request event structure (must match eBPF definition)
struct mds_trace_event {
    __u64 tid;                    // Transaction ID
    __u64 client_id;              // Ceph client entity number
    __u64 submit_time;            // When request was submitted
    __u64 unsafe_reply_time;      // When unsafe reply was received (0 if none)
    __u64 safe_reply_time;        // When safe reply was received
    __u64 unsafe_latency_us;      // Submit to unsafe reply latency
    __u64 safe_latency_us;        // Submit to safe reply latency
    __u32 op;                     // MDS operation type (CEPH_MDS_OP_*)
    __u32 pid;                    // Process ID
    __u32 mds_rank;               // Target MDS rank
    __u32 result;                 // Operation result code
    __u32 attempts;               // Number of send attempts
    __u8 got_unsafe_reply;        // 1 if received unsafe reply
    __u8 got_safe_reply;          // 1 if received safe reply
    __u8 is_write_op;             // 1 if this is a write operation
    char op_name[CEPH_MDS_OP_NAME_MAX]; // Human readable operation name
    char path[CEPH_MDS_PATH_MAX]; // Request path (truncated if needed)
} __attribute__((packed));

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

// Function to get OSD operation string, same as in radostrace
const char * ceph_osd_op_str(int opc) {
    const char *op_str = NULL;
#define GENERATE_CASE_ENTRY(op, opcode, str)	case CEPH_OSD_OP_##op: op_str=str; break;
    switch (opc) {
    __CEPH_FORALL_OSD_OPS(GENERATE_CASE_ENTRY)
    }
    return op_str;
}

// Format ops array with offset/length integrated
static std::string format_ops(const kernel_trace_event* event)
{
    std::stringstream ops_list;
    ops_list << "[";
    bool first = true;
    for (int i = 0; i < event->ops_size && i < CEPH_OSD_MAX_OPS; i++) {
        if (i > 0) ops_list << " ";

        if (!first) 
                ops_list << ","; 
        first = false;
        // Check if this is a call operation with class and method names
        if (event->ops[i] == CEPH_OSD_OP_CALL &&
            strlen(event->cls_ops[i].cls_name) > 0 &&
            strlen(event->cls_ops[i].method_name) > 0) {
            ops_list << "call(" << event->cls_ops[i].cls_name
                     << "." << event->cls_ops[i].method_name << ")";
        } else {
            const char* op_name = ceph_osd_op_str(event->ops[i]);
            if (op_name) {
                ops_list << op_name;
            } else {
                ops_list << "op_" << event->ops[i];
            }

            // Add offset and length for extent-based operations (offset can be 0, check length > 0)
            if (ceph_osd_op_extent(event->ops[i]) && event->length > 0) {
                ops_list << "(" << event->offset << "," << event->length << ")";
            }
        }
    }
    ops_list << "]";
    return ops_list.str();
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct kernel_trace_event *event = (const struct kernel_trace_event *)data;
    struct tm *tm;
    char ts[32];
    char acting_set[256] = "";
    time_t t;
    int pos = 0;

    if (data_sz < sizeof(*event)) {
        fprintf(stderr, "Invalid event size: %zu (expected >= %zu)\n", data_sz, sizeof(*event));
        return 0;
    }

    t = time(NULL);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    // Format acting set as [osd1,osd2,osd3,...]
    if (event->acting_size > 0) {
        pos += snprintf(acting_set + pos, sizeof(acting_set) - pos, "[");
        for (unsigned int i = 0; i < event->acting_size && i < CEPH_PG_MAX_SIZE; i++) {
            if (i > 0)
                pos += snprintf(acting_set + pos, sizeof(acting_set) - pos, ",");
            pos += snprintf(acting_set + pos, sizeof(acting_set) - pos, "%u", 
                           event->acting_osds[i]);
            if (pos >= sizeof(acting_set) - 1) break;
        }
        snprintf(acting_set + pos, sizeof(acting_set) - pos, "]");
    } else {
        snprintf(acting_set, sizeof(acting_set), "[%u]", event->primary_osd);
    }

    // Format object name, ensuring it's null-terminated
    char object_name[CEPH_OID_INLINE_LEN + 1];
    if (event->object_name_len > 0 && event->object_name_len < CEPH_OID_INLINE_LEN) {
        memcpy(object_name, event->object_name, event->object_name_len);
        object_name[event->object_name_len] = '\0';
    } else {
        strcpy(object_name, "<unknown>");
    }

    // Determine operation type string
    const char *op_str;
    if (event->is_read && event->is_write) {
        op_str = "RMW";  // Read-modify-write
    } else if (event->is_read) {
        op_str = "READ";
    } else if (event->is_write) {
        op_str = "WRITE";
    } else {
        op_str = "OTHER";
    }

    // Format ops array (now includes offset/length for extent operations)
    std::string ops_str = format_ops(event);

    printf("%-8s %-8u %-10llu %-16llu %-8llu %-8u %-6s %-20s %-32s %-8u %-30s %-12llu\n",
           ts, event->pid, event->client_id, event->tid, event->pool_id, event->pg_id, op_str, acting_set,
           object_name, event->attempts, ops_str.c_str(), event->latency_us);

    return 0;
}

static int handle_mds_event(void *ctx, void *data, size_t data_sz)
{
    const struct mds_trace_event *event = (const struct mds_trace_event *)data;
    struct tm *tm;
    char ts[32];
    time_t t;

    if (data_sz < sizeof(*event)) {
        fprintf(stderr, "Invalid MDS event size: %zu (expected >= %zu)\n", data_sz, sizeof(*event));
        return 0;
    }

    t = time(NULL);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    // Format latencies
    char unsafe_lat[16] = "-";
    char safe_lat[16];

    if (event->got_unsafe_reply && event->unsafe_latency_us > 0) {
        if (event->unsafe_latency_us >= 1000) {
            snprintf(unsafe_lat, sizeof(unsafe_lat), "%.1fms", event->unsafe_latency_us / 1000.0);
        } else {
            snprintf(unsafe_lat, sizeof(unsafe_lat), "%lluμs", event->unsafe_latency_us);
        }
    }

    if (event->safe_latency_us >= 1000) {
        snprintf(safe_lat, sizeof(safe_lat), "%.1fms", event->safe_latency_us / 1000.0);
    } else {
        snprintf(safe_lat, sizeof(safe_lat), "%lluμs", event->safe_latency_us);
    }

    // Format result
    const char *result_str = (event->result == 0) ? "OK" : "ERR";

    // Clean up path for display (keep leading slash and truncate if too long)
    const char *display_path = event->path;

    char truncated_path[64];
    if (strlen(display_path) > 60) {
        strncpy(truncated_path, display_path, 57);
        strcpy(truncated_path + 57, "...");
        display_path = truncated_path;
    }

    // Output format: TIME PID CLIENT_ID TID MDS OP PATH ATTEMPTS UNSAFE_LAT SAFE_LAT RESULT
    printf("%-8s %-8u %-10llu %-16llu %-3u %-8s %-32s %-8u %-10s %-10s %-6s\n",
           ts, event->pid, event->client_id, event->tid, event->mds_rank,
           event->op_name, display_path, event->attempts, unsafe_lat, safe_lat, result_str);

    return 0;
}

static void print_usage(const char *prog)
{
    printf("Usage: %s [OPTIONS]\n", prog);
    printf("\nOPTIONS:\n");
    printf("  -h, --help        Show this help message\n");
    printf("  -t, --timeout <s> Set execution timeout (default: no timeout)\n");
    printf("  -m, --mode <mode> Tracing mode: osd, mds, or all (default: mds)\n");
    printf("\nDescription:\n");
    printf("  Traces Ceph kernel client requests using kprobes.\n");
    printf("  OSD mode: Shows data requests to OSDs with latencies and operation details.\n");
    printf("  MDS mode: Shows metadata requests to MDS with two-phase reply timing.\n");
    printf("  All mode: Shows both OSD and MDS requests concurrently.\n");
    printf("\nExamples:\n");
    printf("  sudo %s                # Trace MDS requests only (default)\n", prog);
    printf("  sudo %s -m osd         # Trace OSD requests only\n", prog);
    printf("  sudo %s -m all         # Trace both OSD and MDS requests\n", prog);
    printf("  sudo %s -t 30 -m all   # Trace both for 30 seconds\n", prog);
    printf("\nNote: Requires root privileges and kernel v5.8+\n");
}

int main(int argc, char **argv)
{
    struct kfstrace_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    struct ring_buffer *mds_rb = NULL;
    int err = 0;
    int timeout_seconds = 0;
    time_t start_time;

    // Tracing mode configuration
    enum trace_mode { MODE_OSD, MODE_MDS, MODE_ALL } mode = MODE_MDS;

    static const struct option long_options[] = {
        {"help", no_argument, NULL, 'h'},
        {"timeout", required_argument, NULL, 't'},
        {"mode", required_argument, NULL, 'm'},
        {NULL, 0, NULL, 0}
    };

    // Parse command line arguments
    int opt;
    while ((opt = getopt_long(argc, argv, "ht:m:", long_options, NULL)) != -1) {
        switch (opt) {
        case 'h':
            print_usage(argv[0]);
            return 0;
        case 't':
            timeout_seconds = atoi(optarg);
            if (timeout_seconds <= 0) {
                fprintf(stderr, "Invalid timeout value: %s\n", optarg);
                return 1;
            }
            break;
        case 'm':
            if (strcmp(optarg, "osd") == 0) {
                mode = MODE_OSD;
            } else if (strcmp(optarg, "mds") == 0) {
                mode = MODE_MDS;
            } else if (strcmp(optarg, "all") == 0) {
                mode = MODE_ALL;
            } else {
                fprintf(stderr, "Invalid mode: %s (must be osd, mds, or all)\n", optarg);
                return 1;
            }
            break;
        default:
            print_usage(argv[0]);
            return 1;
        }
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Set libbpf strict mode
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    // Load BPF skeleton
    skel = kfstrace_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    // Load BPF program
    err = kfstrace_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %s\n", strerror(-err));
        goto cleanup;
    }

    // Attach BPF programs based on tracing mode
    if (mode == MODE_OSD || mode == MODE_ALL) {
        // Attach OSD-related kprobes
        skel->links.trace_send_request = bpf_program__attach(skel->progs.trace_send_request);
        if (!skel->links.trace_send_request) {
            fprintf(stderr, "Failed to attach send_request kprobe\n");
            err = 1;
            goto cleanup;
        }

        skel->links.trace_osd_dispatch = bpf_program__attach(skel->progs.trace_osd_dispatch);
        if (!skel->links.trace_osd_dispatch) {
            fprintf(stderr, "Failed to attach osd_dispatch kprobe\n");
            err = 1;
            goto cleanup;
        }
    }

    if (mode == MODE_MDS || mode == MODE_ALL) {
        // Attach MDS-related kprobes
        skel->links.trace_prepare_send_request = bpf_program__attach(skel->progs.trace_prepare_send_request);
        if (!skel->links.trace_prepare_send_request) {
            fprintf(stderr, "Failed to attach __prepare_send_request kprobe\n");
            err = 1;
            goto cleanup;
        }

        skel->links.trace_mds_dispatch = bpf_program__attach(skel->progs.trace_mds_dispatch);
        if (!skel->links.trace_mds_dispatch) {
            fprintf(stderr, "Failed to attach mds_dispatch kprobe\n");
            err = 1;
            goto cleanup;
        }
    }

    // Create ring buffers based on tracing mode
    if (mode == MODE_OSD || mode == MODE_ALL) {
        rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
        if (!rb) {
            fprintf(stderr, "Failed to create OSD ring buffer\n");
            err = 1;
            goto cleanup;
        }
    }

    if (mode == MODE_MDS || mode == MODE_ALL) {
        mds_rb = ring_buffer__new(bpf_map__fd(skel->maps.mds_rb), handle_mds_event, NULL, NULL);
        if (!mds_rb) {
            fprintf(stderr, "Failed to create MDS ring buffer\n");
            err = 1;
            goto cleanup;
        }
    }

    // Print appropriate headers based on mode
    if (mode == MODE_OSD) {
        printf("Tracing Ceph kernel OSD requests... Press Ctrl+C to stop.\n");
        printf("%-8s %-8s %-10s %-16s %-8s %-8s %-6s %-20s %-32s %-8s %-30s %-12s\n",
               "TIME", "PID", "CLIENT_ID", "TID", "POOL", "PG", "OP", "ACTING_SET", "OBJECT", "ATTEMPTS", "OPS", "LATENCY(us)");
    } else if (mode == MODE_MDS) {
        printf("Tracing Ceph kernel MDS requests... Press Ctrl+C to stop.\n");
        printf("%-8s %-8s %-10s %-16s %-3s %-8s %-32s %-8s %-10s %-10s %-6s\n",
               "TIME", "PID", "CLIENT_ID", "TID", "MDS", "OP", "PATH", "ATTEMPTS", "UNSAFE_LAT", "SAFE_LAT", "RESULT");
    } else {
        printf("Tracing Ceph kernel OSD and MDS requests... Press Ctrl+C to stop.\n");
    }

    // Set up timeout if specified  
    start_time = time(NULL);
    
    // Poll for events
    while (!exiting) {
        // Poll OSD ring buffer if in OSD or ALL mode
        if (rb) {
            err = ring_buffer__poll(rb, 100 /* timeout in ms */);
            if (err == -EINTR) {
                break;
            }
            if (err < 0) {
                fprintf(stderr, "Error polling OSD ring buffer: %s\n", strerror(-err));
                break;
            }
        }

        // Poll MDS ring buffer if in MDS or ALL mode
        if (mds_rb) {
            err = ring_buffer__poll(mds_rb, 100 /* timeout in ms */);
            if (err == -EINTR) {
                break;
            }
            if (err < 0) {
                fprintf(stderr, "Error polling MDS ring buffer: %s\n", strerror(-err));
                break;
            }
        }

        // If neither ring buffer is active, sleep briefly to avoid busy loop
        if (!rb && !mds_rb) {
            usleep(100000); // 100ms
        }
        
        // Check timeout
        if (timeout_seconds > 0) {
            time_t current_time = time(NULL);
            if (current_time - start_time >= timeout_seconds) {
                printf("\nTimeout reached, exiting...\n");
                break;
            }
        }
    }

cleanup:
    ring_buffer__free(rb);
    ring_buffer__free(mds_rb);
    kfstrace_bpf__destroy(skel);

    return err != 0 ? 1 : 0;
}
