#include "ceph_btf.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_REQUESTS 1024
#define CEPH_PG_MAX_SIZE 8
#define CEPH_OID_INLINE_LEN 24
#define CEPH_OSD_MAX_OPS 3

// MDS tracing constants
#define MAX_MDS_REQUESTS 1024
#define CEPH_MDS_OP_NAME_MAX 32
#define CEPH_MDS_PATH_MAX 64
#define TASK_COMM_LEN 16

// Use the cls_op from bpf_ceph_types.h (method_name[32])
struct cls_op {
    char cls_name[8];
    char method_name[32];
};

struct request_key {
    __u64 client_id;  // Ceph client entity number
    __u64 tid;        // Transaction ID
};

// MDS request tracking key
struct mds_request_key {
    __u64 client_id;  // Ceph client entity number
    __u64 tid;        // MDS transaction ID
};

// MDS request event structure
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
    char comm[TASK_COMM_LEN];     // Process command name
    __u32 attempts;               // Number of send attempts
    __u8 got_unsafe_reply;        // 1 if received unsafe reply
    __u8 got_safe_reply;          // 1 if received safe reply
    __u8 is_write_op;             // 1 if this is a write operation
    char op_name[CEPH_MDS_OP_NAME_MAX]; // Human readable operation name
    char path[CEPH_MDS_PATH_MAX]; // Request path (truncated if needed)
} __attribute__((packed));


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

// Helper to get MDS operation name
static inline void get_mds_op_name(__u32 op, char *name, int max_len)
{
    // Clear the name buffer
    for (int i = 0; i < max_len && i < CEPH_MDS_OP_NAME_MAX; i++) {
        name[i] = '\0';
    }

    // Map common MDS operations to names based on ceph_fs.h values
    switch (op) {
        case 0x00100: // CEPH_MDS_OP_LOOKUP
            __builtin_memcpy(name, "LOOKUP", 7);
            break;
        case 0x00101: // CEPH_MDS_OP_GETATTR
            __builtin_memcpy(name, "GETATTR", 8);
            break;
        case 0x00305: // CEPH_MDS_OP_READDIR
            __builtin_memcpy(name, "READDIR", 8);
            break;
        case 0x01301: // CEPH_MDS_OP_CREATE
            __builtin_memcpy(name, "CREATE", 7);
            break;
        case 0x01203: // CEPH_MDS_OP_UNLINK
            __builtin_memcpy(name, "UNLINK", 7);
            break;
        case 0x01204: // CEPH_MDS_OP_RENAME
            __builtin_memcpy(name, "RENAME", 7);
            break;
        case 0x01220: // CEPH_MDS_OP_MKDIR
            __builtin_memcpy(name, "MKDIR", 6);
            break;
        case 0x01221: // CEPH_MDS_OP_RMDIR
            __builtin_memcpy(name, "RMDIR", 6);
            break;
        case 0x01108: // CEPH_MDS_OP_SETATTR
            __builtin_memcpy(name, "SETATTR", 8);
            break;
        case 0x00302: // CEPH_MDS_OP_OPEN
            __builtin_memcpy(name, "OPEN", 5);
            break;
        default:
            // For unknown operations, show the hex value
            name[0] = 'O';
            name[1] = 'P';
            name[2] = '_';
            // Convert op to hex string (simplified)
            __u32 val = op;
            for (int i = 7; i >= 3; i--) {
                __u8 digit = val & 0xF;
                name[i] = (digit < 10) ? ('0' + digit) : ('A' + digit - 10);
                val >>= 4;
            }
            name[8] = '\0';
            break;
    }
}

// Check if MDS operation is a write operation
static inline int is_mds_write_op(__u32 op)
{
    // Write operations have the CEPH_MDS_OP_WRITE flag (0x001000)
    return (op & 0x001000) != 0;
}

struct kernel_trace_event {
    __u64 tid;
    __u64 client_id;        // Ceph client entity number
    __u64 start_time;
    __u64 end_time;         // Set to 0 in pending requests, filled on completion
    __u64 latency_us;       // Set to 0 in pending requests, calculated on completion
    __u32 primary_osd;
    __u32 acting_osds[CEPH_PG_MAX_SIZE];
    __u32 acting_size;
    __u32 pid;              // Process ID
    __u32 attempts;         // Number of send attempts
    char comm[TASK_COMM_LEN]; // Process command name
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
    __type(value, struct kernel_trace_event);
} pending_requests SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// MDS request tracking maps
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_MDS_REQUESTS);
    __type(key, struct mds_request_key);
    __type(value, struct mds_trace_event);
} pending_mds_requests SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} mds_rb SEC(".maps");

// Helper function to initialize kernel trace event in map (avoids stack overflow)
static __always_inline void initialize_kernel_trace_event(struct request_key *key) {
    struct kernel_trace_event zero_event = {};
    bpf_map_update_elem(&pending_requests, key, &zero_event, BPF_ANY);
}

// Helper function to initialize MDS trace event in map (avoids stack overflow)
static __always_inline void initialize_mds_trace_event(struct mds_request_key *key) {
    struct mds_trace_event zero_event = {};
    bpf_map_update_elem(&pending_mds_requests, key, &zero_event, BPF_ANY);
}

SEC("kprobe/send_request")
int trace_send_request(struct pt_regs *ctx)
{
    struct ceph_osd_request *req = (struct ceph_osd_request *)PT_REGS_PARM1(ctx);
    struct request_key key = {};
    struct kernel_trace_event *info;
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
    struct ceph_entity_name entity_name;
    __u64 client_id = 0;

    // Follow the chain: req->r_osdc->client->msgr to get client entity
    if (bpf_core_read(&osdc, sizeof(osdc), &req->r_osdc) == 0 &&
        bpf_core_read(&client, sizeof(client), &osdc->client) == 0 &&
        bpf_core_read(&entity_name, sizeof(entity_name), &client->msgr.inst.name) == 0) {
        client_id = entity_name.num;
    }
    
    bpf_printk("trace_send_request: client_id=%llu\n", client_id);
    
    // Initialize composite key
    key.client_id = client_id;
    key.tid = tid;

    // Check if this request already exists (retry case)
    struct kernel_trace_event *existing_info = bpf_map_lookup_elem(&pending_requests, &key);
    if (existing_info) {
        // This is a retry - just increment the attempts counter
        existing_info->attempts++;
        bpf_printk("trace_send_request: Retry detected TID=%llu, attempts=%u\n", tid, existing_info->attempts);
        return 0; // Exit early, don't re-initialize the event
    }

    // This is a new request - initialize in map, then get pointer to populate
    initialize_kernel_trace_event(&key);

    info = bpf_map_lookup_elem(&pending_requests, &key);
    if (!info) {
        return 0; // Map operation failed
    }

    // Populate the event via pointer (avoids stack overflow)
    info->tid = tid;
    info->client_id = client_id;
    info->start_time = bpf_ktime_get_ns();
    info->primary_osd = primary_osd;
    info->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&info->comm, sizeof(info->comm));
    info->attempts = 1;  // First attempt
    
    // Read acting set from req->r_t.acting
    struct ceph_osd_request_target *target = &req->r_t;

    // Read acting set size first
    if (bpf_core_read(&info->acting_size, sizeof(info->acting_size), &target->acting.size) == 0) {
        if (info->acting_size > CEPH_PG_MAX_SIZE)
            info->acting_size = CEPH_PG_MAX_SIZE;

        // Copy acting OSDs array directly
        bpf_core_read(&info->acting_osds, sizeof(int) * info->acting_size, &target->acting.osds);
    }

    // Read target object ID fields directly
    int name_len;
    if (bpf_core_read(&name_len, sizeof(name_len), &target->target_oid.name_len) == 0) {
        info->object_name_len = name_len;
        if (info->object_name_len > CEPH_OID_INLINE_LEN - 1)
            info->object_name_len = CEPH_OID_INLINE_LEN - 1;

        // Try to read the inline name first (most common case)
        bpf_core_read_str(info->object_name, info->object_name_len + 1, &target->target_oid.inline_name);
    }

    // Read pool and PG information from target->spgid.pgid (calculated PG)
    struct ceph_spg spgid;
    if (bpf_core_read(&spgid, sizeof(spgid), &target->spgid) == 0) {
        info->pool_id = spgid.pgid.pool;
        info->pg_id = spgid.pgid.seed;  // This should be the calculated PG ID
        bpf_printk("trace_send_request: pool_id=%llu, pg_id=%u\n", info->pool_id, info->pg_id);
    }

    // Read flags from target and determine read/write based on CEPH_OSD_FLAG_WRITE
    __u32 flags;
    if (bpf_core_read(&flags, sizeof(flags), &target->flags) == 0) {
        info->is_write = (flags & CEPH_OSD_FLAG_WRITE) ? 1 : 0;
        info->is_read = !info->is_write;  // If not write, then it's read
        bpf_printk("trace_send_request: flags=0x%x, is_write=%u, is_read=%u\n", flags, info->is_write, info->is_read);
    }
    
    // Read all operations from the r_ops array
    __u32 r_num_ops;
    if (bpf_core_read(&r_num_ops, sizeof(r_num_ops), &req->r_num_ops) == 0 && r_num_ops > 0) {
        info->ops_size = r_num_ops > CEPH_OSD_MAX_OPS ? CEPH_OSD_MAX_OPS : r_num_ops;
        info->offset = 0;
        info->length = 0;

        // Extract all operation types
        for (int i = 0; i < info->ops_size && i < CEPH_OSD_MAX_OPS; i++) {
            __u16 op_type;
            if (bpf_core_read(&op_type, sizeof(op_type), &req->r_ops[i].op) == 0) {
                info->ops[i] = op_type;


                // Extract offset and length for extent operations (from first extent op only)
                if (ceph_osd_op_extent(op_type) && info->offset == 0 && info->length == 0) {
                    bpf_core_read(&info->offset, sizeof(info->offset), &req->r_ops[i].extent.offset);
                    bpf_core_read(&info->length, sizeof(info->length), &req->r_ops[i].extent.length);
                    bpf_printk("trace_send_request: offset=%llu, length=%llu\n", info->offset, info->length);
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
                        if (class_len >= sizeof(info->cls_ops[i].cls_name)) {
                            class_len = sizeof(info->cls_ops[i].cls_name) - 1;
                        }
                        bpf_core_read_str(info->cls_ops[i].cls_name, class_len + 1, class_name);
                    } else {
                        info->cls_ops[i].cls_name[0] = '\0';
                    }

                    // Read method name pointer and length
                    if (bpf_core_read(&method_name, sizeof(method_name), &req->r_ops[i].cls.method_name) == 0 &&
                        bpf_core_read(&method_len, sizeof(method_len), &req->r_ops[i].cls.method_len) == 0 &&
                        method_name != NULL && method_len > 0) {

                        // Limit method name length to our buffer size
                        if (method_len >= sizeof(info->cls_ops[i].method_name)) {
                            method_len = sizeof(info->cls_ops[i].method_name) - 1;
                        }
                        bpf_core_read_str(info->cls_ops[i].method_name, method_len + 1, method_name);
                    } else {
                        info->cls_ops[i].method_name[0] = '\0';
                    }
                }
            }
        }
    }

    // Data is already in map, no need to update
    bpf_printk("trace_send_request: stored key client_id=%llu tid=%llu\n", key.client_id, key.tid);
    
    return 0;
}

SEC("kprobe/osd_dispatch")
int trace_osd_dispatch(struct pt_regs *ctx)
{
    struct ceph_connection *con = (struct ceph_connection *)PT_REGS_PARM1(ctx);
    struct ceph_msg *msg = (struct ceph_msg *)PT_REGS_PARM2(ctx);
    struct request_key key = {};
    struct kernel_trace_event *info;
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

    // Copy the entire structure from pending request
    *event = *info;

    // Update completion fields
    event->end_time = end_time;
    event->latency_us = (end_time - info->start_time) / 1000;
    
    bpf_ringbuf_submit(event, 0);
    
cleanup:
    bpf_map_delete_elem(&pending_requests, &key);
    return 0;
}

// MDS request submission hook - traces when request is prepared for sending (TID assigned)
SEC("kprobe/__prepare_send_request")
int trace_prepare_send_request(struct pt_regs *ctx)
{
    bpf_printk("=== MDS PREPARE_SEND: Function called ===\n");

    struct ceph_mds_session *session = (struct ceph_mds_session *)PT_REGS_PARM1(ctx);
    struct ceph_mds_request *req = (struct ceph_mds_request *)PT_REGS_PARM2(ctx);
    bool drop_cap_releases = (bool)PT_REGS_PARM3(ctx);

    if (!req) {
        bpf_printk("MDS PREPARE_SEND: req is NULL\n");
        return 0;
    }

    struct mds_request_key key = {};
    struct mds_trace_event *event;
    __u64 tid;
    __u32 op;
    __u32 mds_rank;

    // Read transaction ID
    if (bpf_core_read(&tid, sizeof(tid), &req->r_tid) != 0) {
        bpf_printk("MDS PREPARE_SEND: FAILED to read TID from req\n");
        return 0;
    }

    // Read operation type
    if (bpf_core_read(&op, sizeof(op), &req->r_op) != 0) {
        bpf_printk("MDS PREPARE_SEND: FAILED to read operation from req\n");
        return 0;
    }

    bpf_printk("MDS PREPARE_SEND: SUCCESS - TID=%llu OP=0x%x\n", tid, op);

    // Extract client ID from session->s_mdsc->fsc->client
    struct ceph_mds_client *mdsc;
    struct ceph_client *client;
    struct ceph_entity_name entity_name;
    __u64 client_id = 0;

    struct ceph_fs_client *fsc;
    if (bpf_core_read(&mdsc, sizeof(mdsc), &session->s_mdsc) == 0 && mdsc &&
        bpf_core_read(&fsc, sizeof(fsc), &mdsc->fsc) == 0 && fsc &&
        bpf_core_read(&client, sizeof(client), &fsc->client) == 0 &&
        bpf_core_read(&entity_name, sizeof(entity_name), &client->msgr.inst.name) == 0) {
        client_id = entity_name.num;
        bpf_printk("MDS PREPARE_SEND: CLIENT_ID=%llu\n", client_id);
    } else {
        bpf_printk("MDS PREPARE_SEND: Failed to get CLIENT_ID\n");
    }

    // Read target MDS rank from session (now directly available)
    if (session && bpf_core_read(&mds_rank, sizeof(mds_rank), &session->s_mds) == 0) {
        bpf_printk("MDS PREPARE_SEND: MDS_RANK=%u\n", mds_rank);
    } else {
        mds_rank = 0;
        bpf_printk("MDS PREPARE_SEND: Failed to get MDS rank\n");
    }

    // Initialize the key for lookup
    key.client_id = client_id;
    key.tid = tid;

    // Check if this request already exists (retry case)
    struct mds_trace_event *existing_event = bpf_map_lookup_elem(&pending_mds_requests, &key);
    if (existing_event) {
        // This is a retry - just increment the attempts counter
        existing_event->attempts++;
        bpf_printk("MDS PREPARE_SEND: Retry detected TID=%llu, attempts=%u\n", tid, existing_event->attempts);
        return 0; // Exit early, don't re-initialize the event
    }

    // This is a new request - initialize in map, then get pointer to populate
    initialize_mds_trace_event(&key);

    event = bpf_map_lookup_elem(&pending_mds_requests, &key);
    if (!event) {
        return 0; // Map operation failed
    }

    // Populate the event via pointer (avoids stack overflow)
    event->tid = tid;
    event->client_id = client_id;
    event->submit_time = bpf_ktime_get_ns();
    event->unsafe_reply_time = 0;
    event->safe_reply_time = 0;
    event->unsafe_latency_us = 0;
    event->safe_latency_us = 0;
    event->op = op;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->mds_rank = mds_rank;
    event->result = 0;
    event->attempts = 1;  // First attempt
    event->got_unsafe_reply = 0;
    event->got_safe_reply = 0;
    event->is_write_op = is_mds_write_op(op);

    // Get operation name
    get_mds_op_name(op, event->op_name, CEPH_MDS_OP_NAME_MAX);

    // Extract filename/directory name from dentry (r_path1/r_path2 are not set yet)
    // TODO Path can get from ceph_mds_build_path. For now we just get the filename
    event->path[0] = '\0';

    struct dentry *dentry;
    const unsigned char *filename;
    __u32 filename_len = 0;

    if (bpf_core_read(&dentry, sizeof(dentry), &req->r_dentry) == 0 && dentry) {
        if (bpf_core_read(&filename, sizeof(filename), &dentry->d_name.name) == 0 && filename &&
            bpf_core_read(&filename_len, sizeof(filename_len), &dentry->d_name.len) == 0 && filename_len > 0) {

            // Limit filename length to our buffer size
            if (filename_len >= CEPH_MDS_PATH_MAX) {
                filename_len = CEPH_MDS_PATH_MAX - 1;
            }

            // Read just the dentry name (filename or directory name)
            if (bpf_core_read_str(event->path, filename_len + 1, filename) <= 0) {
                event->path[0] = '\0';
            }
            bpf_printk("MDS PREPARE_SEND: dentry name='%s'\n", event->path);
        }
    }

    // Fallback if no dentry name available
    if (event->path[0] == '\0') {
        event->path[0] = '?';
        event->path[1] = '\0';
    }

    // Data is already in map, no need to update
    bpf_printk("MDS PREPARE_SEND: Stored TID=%llu CLIENT_ID=%llu\n", tid, client_id);

    return 0;
}

// MDS message dispatch hook - traces all MDS messages including replies
SEC("kprobe/mds_dispatch")
int trace_mds_dispatch(struct pt_regs *ctx)
{
    struct ceph_connection *con = (struct ceph_connection *)PT_REGS_PARM1(ctx);
    struct ceph_msg *msg = (struct ceph_msg *)PT_REGS_PARM2(ctx);

    // Check message type first - we only care about CEPH_MSG_CLIENT_REPLY (26)
    __u16 msg_type;
    if (bpf_core_read(&msg_type, sizeof(msg_type), &msg->hdr.type) != 0) {
        return 0;
    }

    if (msg_type != 26) { // CEPH_MSG_CLIENT_REPLY
        return 0; // Exit early if not a client reply
    }

    bpf_printk("=== MDS DISPATCH: CLIENT_REPLY message ===\n");

    struct mds_request_key key = {};
    struct mds_trace_event *event;
    struct mds_trace_event *output_event;
    __u64 tid;
    __u64 current_time;
    __u8 safe_flag;
    __u32 result;

    // Extract TID from message header
    struct ceph_msg_header *hdr = &msg->hdr;
    if (bpf_core_read(&tid, sizeof(tid), &hdr->tid) != 0) {
        bpf_printk("MDS DISPATCH: Failed to read TID\n");
        return 0;
    }

    bpf_printk("MDS DISPATCH: TID=%llu\n", tid);

    // Extract session from connection to get client ID
    struct ceph_mds_session *session;
    if (bpf_core_read(&session, sizeof(session), &con->private) != 0 || !session) {
        return 0; // Can't get session from connection
    }

    // Extract client ID from session
    struct ceph_mds_client *mdsc;
    struct ceph_client *client;
    struct ceph_entity_name entity_name;
    __u64 client_id = 0;

    struct ceph_fs_client *fsc;
    if (bpf_core_read(&mdsc, sizeof(mdsc), &session->s_mdsc) == 0 &&
        bpf_core_read(&fsc, sizeof(fsc), &mdsc->fsc) == 0 && fsc &&
        bpf_core_read(&client, sizeof(client), &fsc->client) == 0 &&
        bpf_core_read(&entity_name, sizeof(entity_name), &client->msgr.inst.name) == 0) {
        client_id = entity_name.num;
    }

    // Form the key and check if we're tracking this request
    key.client_id = client_id;
    key.tid = tid;

    // Look up the pending request - if not found, this isn't a client reply we care about
    event = bpf_map_lookup_elem(&pending_mds_requests, &key);
    if (!event) {
        bpf_printk("MDS DISPATCH: No pending request for TID=%llu\n", tid);
        return 0; // Not tracking this request, so ignore
    }

    bpf_printk("MDS DISPATCH: Found pending TID=%llu\n", tid);

    // Now we know this is a client reply - read reply head to get safe flag and result
    struct ceph_mds_reply_head *head;
    if (bpf_core_read(&head, sizeof(head), &msg->front.iov_base) != 0) {
        return 0;
    }

    if (bpf_core_read(&safe_flag, sizeof(safe_flag), &head->safe) != 0 ||
        bpf_core_read(&result, sizeof(result), &head->result) != 0) {
        return 0;
    }

    bpf_printk("trace_mds_handle_reply: tid=%llu safe=%u result=%d\n", tid, safe_flag, result);

    // We already have the event from the lookup above

    current_time = bpf_ktime_get_ns();
    event->result = result;

    if (safe_flag) {
        // SAFE REPLY
        event->got_safe_reply = 1;
        event->safe_reply_time = current_time;
        event->safe_latency_us = (current_time - event->submit_time) / 1000;

        // For write operations that got unsafe reply first, this completes the two-phase pattern
        // For read operations, this is the only reply

        // Reserve space in ring buffer and emit the completed event
        output_event = bpf_ringbuf_reserve(&mds_rb, sizeof(struct mds_trace_event), 0);
        if (output_event) {
            *output_event = *event;
            bpf_ringbuf_submit(output_event, 0);
        }

        // Remove from pending requests map
        bpf_map_delete_elem(&pending_mds_requests, &key);

        bpf_printk("trace_mds_handle_reply: completed request (safe reply) tid=%llu\n", tid);

    } else {
        // UNSAFE REPLY
        event->got_unsafe_reply = 1;
        event->unsafe_reply_time = current_time;
        event->unsafe_latency_us = (current_time - event->submit_time) / 1000;

        // Update the pending request but don't emit event yet - wait for safe reply
        bpf_map_update_elem(&pending_mds_requests, &key, event, BPF_EXIST);

        bpf_printk("trace_mds_handle_reply: got unsafe reply, waiting for safe reply tid=%llu\n", tid);
    }

    return 0;
}
