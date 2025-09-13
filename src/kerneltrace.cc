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

#include "kerneltrace.skel.h"
#include "bpf_ceph_types.h"

#define CEPH_PG_MAX_SIZE 8
#define CEPH_OID_INLINE_LEN 32
#define CEPH_OSD_MAX_OPS 3


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
    char object_name[CEPH_OID_INLINE_LEN];
    __u32 object_name_len;
    __u16 op_type;
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

// Format ops array similar to radostrace
static std::string format_ops(const kernel_trace_event* event)
{
    std::stringstream ops_list;
    ops_list << "[";
    for (int i = 0; i < event->ops_size && i < CEPH_OSD_MAX_OPS; i++) {
        if (i > 0) ops_list << " ";
        
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

    // Format ops array
    std::string ops_str = format_ops(event);
    
    // Format offset and length (only show if it's an extent operation)
    std::string offset_str = (event->offset > 0) ? std::to_string(event->offset) : "";
    std::string length_str = (event->length > 0) ? std::to_string(event->length) : "";
    
    printf("%-8s %-8u %-10llu %-16llu %-8llu %-8u %-6s %-20s %-32s %-20s %-10s %-10s %-10llu us\n",
           ts, event->pid, event->client_id, event->tid, event->pool_id, event->pg_id, op_str, acting_set,
           object_name, ops_str.c_str(), offset_str.c_str(), length_str.c_str(), event->latency_us);

    return 0;
}

static void print_usage(const char *prog)
{
    printf("Usage: %s [OPTIONS]\n", prog);
    printf("\nOPTIONS:\n");
    printf("  -h, --help        Show this help message\n");
    printf("  -t, --timeout <s> Set execution timeout (default: no timeout)\n");
    printf("\nDescription:\n");
    printf("  Traces Ceph kernel client requests to OSDs using kprobes.\n");
    printf("  Shows request latencies, target OSDs, and operation details.\n");
    printf("\nExamples:\n");
    printf("  sudo %s                # Trace all kernel Ceph client activity\n", prog);
    printf("  sudo %s -t 30          # Trace for 30 seconds then exit\n", prog);
    printf("\nNote: Requires root privileges and kernel v5.8+\n");
}

int main(int argc, char **argv)
{
    struct kerneltrace_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    int err = 0;
    int timeout_seconds = 0;
    time_t start_time;
    
    static const struct option long_options[] = {
        {"help", no_argument, NULL, 'h'},
        {"timeout", required_argument, NULL, 't'},
        {NULL, 0, NULL, 0}
    };

    // Parse command line arguments
    int opt;
    while ((opt = getopt_long(argc, argv, "ht:", long_options, NULL)) != -1) {
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
    skel = kerneltrace_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    // Load BPF program
    err = kerneltrace_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %s\n", strerror(-err));
        goto cleanup;
    }

    // Attach BPF programs
    err = kerneltrace_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %s\n", strerror(-err));
        goto cleanup;
    }

    // Create ring buffer
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        err = 1;
        goto cleanup;
    }

    printf("Tracing Ceph kernel client requests... Press Ctrl+C to stop.\n");
    printf("%-8s %-8s %-10s %-16s %-8s %-8s %-6s %-20s %-32s %-20s %-10s %-10s %-10s\n", 
           "TIME", "PID", "CLIENT_ID", "TID", "POOL", "PG", "OP", "ACTING_SET", "OBJECT", "OPS", "OFFSET", "LENGTH", "LATENCY");

    // Set up timeout if specified  
    start_time = time(NULL);
    
    // Poll for events
    while (!exiting) {
        err = ring_buffer__poll(rb, 1000 /* timeout in ms */);
        if (err == -EINTR) {
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %s\n", strerror(-err));
            break;
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
    kerneltrace_bpf__destroy(skel);

    return err != 0 ? 1 : 0;
}
