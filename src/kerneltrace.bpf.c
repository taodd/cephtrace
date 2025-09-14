#include "ceph_btf.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_REQUESTS 1024
#define CEPH_PG_MAX_SIZE 8
#define CEPH_OID_INLINE_LEN 32
#define CEPH_OSD_MAX_OPS 3

// Use the cls_op from bpf_ceph_types.h (method_name[32])
struct cls_op {
    char cls_name[8];
    char method_name[32];
};

struct request_key {
    __u64 client_id;  // Ceph client entity number
    __u64 tid;        // Transaction ID
};


// Check if operation is extent-based (uses offset/length)
static inline int ceph_osd_op_extent(int op)
{
    // Use enum values from kernel BTF (ceph_btf.h)
    return op == CEPH_OSD_OP_READ ||
           op == CEPH_OSD_OP_SPARSE_READ ||  
           op == CEPH_OSD_OP_SYNC_READ ||
           op == CEPH_OSD_OP_WRITE ||
           op == CEPH_OSD_OP_WRITEFULL ||
           op == CEPH_OSD_OP_ZERO ||
           op == CEPH_OSD_OP_APPEND ||
           op == CEPH_OSD_OP_MAPEXT;
}

// Check if operation is a class call
static inline int ceph_osd_op_call(int op)
{
    // Find CEPH_OSD_OP_CALL value from kernel BTF
    return op == CEPH_OSD_OP_CALL;
}

struct kernel_request_info {
    __u64 tid;
    __u64 client_id;        // Ceph client entity number
    __u64 start_time;
    __u32 primary_osd;
    __u32 acting_osds[CEPH_PG_MAX_SIZE];
    __u32 acting_size;
    __u32 pid;              // Process ID
    char object_name[CEPH_OID_INLINE_LEN];
    __u32 object_name_len;
    __u8 is_read;
    __u8 is_write;
    __u64 pool_id;          // Pool ID
    __u32 pg_id;            // Actual PG ID (seed % pg_num)
    __u16 ops[CEPH_OSD_MAX_OPS];  // Array of operation types
    __u8 ops_size;          // Number of operations
    __u64 offset;           // Offset for extent operations
    __u64 length;           // Length for extent operations
    struct cls_op cls_ops[CEPH_OSD_MAX_OPS];  // Class operation names
};

struct kernel_trace_event {
    __u64 tid;
    __u64 client_id;        // Ceph client entity number
    __u64 start_time;
    __u64 end_time;
    __u64 latency_us;
    __u32 primary_osd;
    __u32 acting_osds[CEPH_PG_MAX_SIZE];
    __u32 acting_size;
    __u32 pid;              // Process ID
    char object_name[CEPH_OID_INLINE_LEN];
    __u32 object_name_len;
    __u8 is_read;
    __u8 is_write;
    __u64 pool_id;          // Pool ID
    __u32 pg_id;            // Actual PG ID (seed % pg_num)
    __u16 ops[CEPH_OSD_MAX_OPS];  // Array of operation types
    __u8 ops_size;          // Number of operations
    __u64 offset;           // Offset for extent operations
    __u64 length;           // Length for extent operations
    struct cls_op cls_ops[CEPH_OSD_MAX_OPS];  // Class operation names
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_REQUESTS);
    __type(key, struct request_key);  // client_id + tid
    __type(value, struct kernel_request_info);
} pending_requests SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("kprobe/send_request")
int trace_send_request(struct pt_regs *ctx)
{
    struct ceph_osd_request *req = (struct ceph_osd_request *)PT_REGS_PARM1(ctx);
    struct kernel_request_info info = {};
    struct request_key key = {};
    __u64 tid;
    __u32 primary_osd;
    
    bpf_printk("trace_send_request: entered\n");
    
    // Read transaction ID
    if (bpf_core_read(&tid, sizeof(tid), &req->r_tid) != 0) {
        bpf_printk("trace_send_request: failed to read tid\n");
        return 0;
    }
    
    bpf_printk("trace_send_request: tid=%llu\n", tid);
        
    // Read primary OSD ID from req->r_osd->o_osd
    struct ceph_osd *osd;
    if (bpf_core_read(&osd, sizeof(osd), &req->r_osd) != 0)
        return 0;
        
    if (bpf_core_read(&primary_osd, sizeof(primary_osd), &osd->o_osd) != 0)
        return 0;
    
    // Extract Ceph client ID from req->r_osdc->client->msgr structure
    struct ceph_osd_client *osdc;
    struct ceph_client *client;
    struct ceph_messenger *msgr;
    struct ceph_entity_name entity_name;
    __u64 client_id = 0;
    
    // Follow the chain: req->r_osdc->client->msgr to get client entity
    if (bpf_core_read(&osdc, sizeof(osdc), &req->r_osdc) == 0 &&
        bpf_core_read(&client, sizeof(client), &osdc->client) == 0) {
        // Try to read the client entity name from the messenger
        if (bpf_core_read(&entity_name, sizeof(entity_name), &client->msgr.inst.name) == 0) {
            client_id = entity_name.num;
        }
    }
    
    bpf_printk("trace_send_request: client_id=%llu\n", client_id);
    
    // Initialize composite key
    key.client_id = client_id;
    key.tid = tid;
    
    info.tid = tid;
    info.client_id = client_id;
    info.start_time = bpf_ktime_get_ns();
    info.primary_osd = primary_osd;
    info.pid = bpf_get_current_pid_tgid() >> 32;
    
    // Read acting set from req->r_t.acting
    struct ceph_osd_request_target *target = &req->r_t;
    
    // Read acting set size first
    if (bpf_core_read(&info.acting_size, sizeof(info.acting_size), &target->acting.size) == 0) {
        if (info.acting_size > CEPH_PG_MAX_SIZE)
            info.acting_size = CEPH_PG_MAX_SIZE;
        
        // Copy acting OSDs array directly
        bpf_core_read(&info.acting_osds, sizeof(int) * info.acting_size, &target->acting.osds);
    }
    
    // Read target object ID fields directly
    int name_len;
    if (bpf_core_read(&name_len, sizeof(name_len), &target->target_oid.name_len) == 0) {
        info.object_name_len = name_len;
        if (info.object_name_len > CEPH_OID_INLINE_LEN - 1)
            info.object_name_len = CEPH_OID_INLINE_LEN - 1;
        
        // Try to read the inline name first (most common case)
        bpf_core_read_str(info.object_name, info.object_name_len + 1, &target->target_oid.inline_name);
    }
    
    // Read pool and PG information from target->spgid.pgid (calculated PG)
    struct ceph_spg spgid;
    if (bpf_core_read(&spgid, sizeof(spgid), &target->spgid) == 0) {
        info.pool_id = spgid.pgid.pool;
        info.pg_id = spgid.pgid.seed;  // This should be the calculated PG ID
        bpf_printk("trace_send_request: pool_id=%llu, pg_id=%u\n", info.pool_id, info.pg_id);
    }

    // Read flags from target and determine read/write based on CEPH_OSD_FLAG_WRITE
    __u32 flags;
    if (bpf_core_read(&flags, sizeof(flags), &target->flags) == 0) {
        info.is_write = (flags & CEPH_OSD_FLAG_WRITE) ? 1 : 0;
        info.is_read = !info.is_write;  // If not write, then it's read
        bpf_printk("trace_send_request: flags=0x%x, is_write=%u, is_read=%u\n", flags, info.is_write, info.is_read);
    }
    
    // Read all operations from the r_ops array
    __u32 r_num_ops;
    if (bpf_core_read(&r_num_ops, sizeof(r_num_ops), &req->r_num_ops) == 0 && r_num_ops > 0) {
        info.ops_size = r_num_ops > CEPH_OSD_MAX_OPS ? CEPH_OSD_MAX_OPS : r_num_ops;
        info.offset = 0;
        info.length = 0;
        
        // Extract all operation types
        for (int i = 0; i < info.ops_size && i < CEPH_OSD_MAX_OPS; i++) {
            __u16 op_type;
            if (bpf_core_read(&op_type, sizeof(op_type), &req->r_ops[i].op) == 0) {
                info.ops[i] = op_type;
                
                
                // Extract offset and length for extent operations
                if (ceph_osd_op_extent(op_type)) {
                    __u64 offset, length;
                    if (bpf_core_read(&offset, sizeof(offset), &req->r_ops[i].extent.offset) == 0) {
                        info.offset = offset;
                        bpf_printk("trace_send_request: offset=%llu\n", offset);
                    }
                    if (bpf_core_read(&length, sizeof(length), &req->r_ops[i].extent.length) == 0) {
                        info.length = length;
                        bpf_printk("trace_send_request: length=%llu\n", length);
                    }
                } else if (ceph_osd_op_call(op_type)) {
                    // Extract class name and method name for call operations
                    const char *class_name = NULL;
                    const char *method_name = NULL;
                    __u8 class_len = 0;
                    __u8 method_len = 0;
                    
                    // Read class name pointer and length
                    if (bpf_core_read(&class_name, sizeof(class_name), &req->r_ops[i].cls.class_name) == 0 &&
                        bpf_core_read(&class_len, sizeof(class_len), &req->r_ops[i].cls.class_len) == 0 &&
                        class_name != NULL && class_len > 0) {
                        
                        // Limit class name length to our buffer size
                        if (class_len >= sizeof(info.cls_ops[i].cls_name)) {
                            class_len = sizeof(info.cls_ops[i].cls_name) - 1;
                        }
                        bpf_core_read_str(info.cls_ops[i].cls_name, class_len + 1, class_name);
                    } else {
                        info.cls_ops[i].cls_name[0] = '\0';
                    }
                    
                    // Read method name pointer and length
                    if (bpf_core_read(&method_name, sizeof(method_name), &req->r_ops[i].cls.method_name) == 0 &&
                        bpf_core_read(&method_len, sizeof(method_len), &req->r_ops[i].cls.method_len) == 0 &&
                        method_name != NULL && method_len > 0) {
                        
                        // Limit method name length to our buffer size  
                        if (method_len >= sizeof(info.cls_ops[i].method_name)) {
                            method_len = sizeof(info.cls_ops[i].method_name) - 1;
                        }
                        bpf_core_read_str(info.cls_ops[i].method_name, method_len + 1, method_name);
                    } else {
                        info.cls_ops[i].method_name[0] = '\0';
                    }
                }
            }
        }
    }
    
    bpf_map_update_elem(&pending_requests, &key, &info, BPF_ANY);
    bpf_printk("trace_send_request: stored key client_id=%llu tid=%llu\n", key.client_id, key.tid);
    
    return 0;
}

SEC("kprobe/osd_dispatch")
int trace_osd_dispatch(struct pt_regs *ctx)
{
    struct ceph_connection *con = (struct ceph_connection *)PT_REGS_PARM1(ctx);
    struct ceph_msg *msg = (struct ceph_msg *)PT_REGS_PARM2(ctx);
    struct request_key key = {};
    struct kernel_request_info *info;
    struct kernel_trace_event *event;
    __u64 end_time;
    
    bpf_printk("trace_osd_dispatch: entered\n");
    
    // Extract TID and client ID from message header
    if (bpf_core_read(&key.tid, sizeof(key.tid), &msg->hdr.tid) != 0) {
        bpf_printk("trace_osd_dispatch: failed to read tid\n");
        return 0;
    }
    
    bpf_printk("trace_osd_dispatch: tid=%llu\n", key.tid);
    
    // Extract client ID from the OSD connection's osdc->client->msgr.inst.name
    struct ceph_osd *osd;
    struct ceph_osd_client *osdc;
    struct ceph_client *client;
    struct ceph_entity_name entity_name;
    __u64 client_id = 0;
    
    if (bpf_core_read(&osd, sizeof(osd), &con->private) == 0 &&
        bpf_core_read(&osdc, sizeof(osdc), &osd->o_osdc) == 0 &&
        bpf_core_read(&client, sizeof(client), &osdc->client) == 0) {
        if (bpf_core_read(&entity_name, sizeof(entity_name), &client->msgr.inst.name) == 0) {
            client_id = entity_name.num;
        }
    }
    
    key.client_id = client_id;
    bpf_printk("trace_osd_dispatch: client_id=%llu\n", key.client_id);
    
    info = bpf_map_lookup_elem(&pending_requests, &key);
    if (!info) {
        bpf_printk("trace_osd_dispatch: no pending request found for client_id=%llu tid=%llu\n", key.client_id, key.tid);
        return 0;
    }
    
    bpf_printk("trace_osd_dispatch: found pending request\n");
    
    end_time = bpf_ktime_get_ns();
    
    // Reserve space in ring buffer
    event = bpf_ringbuf_reserve(&rb, sizeof(struct kernel_trace_event), 0);
    if (!event)
        goto cleanup;
    
    event->tid = key.tid;
    event->client_id = info->client_id;
    event->start_time = info->start_time;
    event->end_time = end_time;
    event->latency_us = (end_time - info->start_time) / 1000;
    event->primary_osd = info->primary_osd;
    event->acting_size = info->acting_size;
    event->pid = info->pid;
    
    // Copy acting OSDs array
    for (int i = 0; i < info->acting_size && i < CEPH_PG_MAX_SIZE; i++) {
        event->acting_osds[i] = info->acting_osds[i];
    }
    
    // Copy object name with proper bounds checking
    event->object_name_len = info->object_name_len;
    if (event->object_name_len >= CEPH_OID_INLINE_LEN) {
        event->object_name_len = CEPH_OID_INLINE_LEN - 1;
    }
    
    for (int i = 0; i < event->object_name_len && i < CEPH_OID_INLINE_LEN - 1; i++) {
        event->object_name[i] = info->object_name[i];
    }
    
    // Ensure null termination with bounds check
    if (event->object_name_len < CEPH_OID_INLINE_LEN) {
        event->object_name[event->object_name_len] = '\0';
    }
    
    // Copy operation type information
    event->is_read = info->is_read;
    event->is_write = info->is_write;
    
    // Copy pool and PG information
    event->pool_id = info->pool_id;
    event->pg_id = info->pg_id;
    
    // Copy ops information
    event->ops_size = info->ops_size;
    event->offset = info->offset;
    event->length = info->length;
    for (int i = 0; i < info->ops_size && i < CEPH_OSD_MAX_OPS; i++) {
        event->ops[i] = info->ops[i];
    }
    
    // Copy class operation information
    for (int i = 0; i < info->ops_size && i < CEPH_OSD_MAX_OPS; i++) {
        // Copy class name strings directly (they are already null-terminated from send_request)
        for (int j = 0; j < sizeof(info->cls_ops[i].cls_name) && j < sizeof(event->cls_ops[i].cls_name); j++) {
            event->cls_ops[i].cls_name[j] = info->cls_ops[i].cls_name[j];
            if (event->cls_ops[i].cls_name[j] == '\0') break;
        }
        
        // Copy method name strings directly
        for (int j = 0; j < sizeof(info->cls_ops[i].method_name) && j < sizeof(event->cls_ops[i].method_name); j++) {
            event->cls_ops[i].method_name[j] = info->cls_ops[i].method_name[j];
            if (event->cls_ops[i].method_name[j] == '\0') break;
        }
    }
    
    bpf_ringbuf_submit(event, 0);
    
cleanup:
    bpf_map_delete_elem(&pending_requests, &key);
    return 0;
}