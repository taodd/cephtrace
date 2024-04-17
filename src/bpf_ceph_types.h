#ifndef BPF_OSD_TYPES_H
#define BPF_OSD_TYPES_H

#define MSG_OSD_REPOP 112
#define MSG_OSD_REPOPREPLY 113

#define MSG_OSD_OP 42
#define MSG_OSD_OPREPLY 43

#define MSG_OSD_EC_WRITE 108
#define MSG_OSD_EC_WRITE_REPLY 109
#define MSG_OSD_EC_READ 110
#define MSG_OSD_EC_READ_REPLY 111

#define CEPH_OSD_FLAG_READ 0x0010
#define CEPH_OSD_FLAG_WRITE 0x0020
 
static const __u8 flag_queued_for_pg=1 << 0;
static const __u8 flag_reached_pg =  1 << 1;
static const __u8 flag_delayed =     1 << 2;
static const __u8 flag_started =     1 << 3;
static const __u8 flag_sub_op_sent = 1 << 4;
static const __u8 flag_commit_sent = 1 << 5;

struct client_op_k {
  __u64 cid;
  __u64 tid;
};

struct client_op_v {
  __u64 cid;
  __u64 tid;
  __u16 rw;
  __u64 sent_stamp;
  __u64 finish_stamp;
  __u32 target_osd;
  __u32 pid; //process id
  //TODO peer OSDs
  //__u64 m_pool;
  //__u64 m_seed;
  //__u64 wb;
  //__u64 rb;
  //__u64 offset;
  char object_name[64];
  __u64 m_pool;
  __u32 m_seed;
  int acting[8];
};

struct op_k {
  __u32 pid;    // process id
  __u64 owner;  // client id
  __u64 tid;    // request id from the client
};

struct ctx_k {
  __u32 pid;
  __u32 seqid;
  __u64 start_stamp;
};

struct peers_info {
    int peer1;
    int peer2;
    __u64 sent_stamp;
    __u64 recv_stamp1;
    __u64 recv_stamp2;
};

struct delay_info {
    int cnt;
    char delays[5][32];
};

struct bluestore_lat_v {
  __u32 pid;
  int idx;
  __u64 lat;
};

struct op_v {
  __u32 pid;
  unsigned long long owner;
  unsigned long long tid;
  __u16 op_type;
  unsigned long long recv_stamp;
  unsigned long long throttle_stamp;
  unsigned long long recv_complete_stamp;
  unsigned long long dispatch_stamp;
  unsigned long long enqueue_stamp;
  unsigned long long dequeue_stamp;
  unsigned long long execute_ctx_stamp;
  unsigned long long submit_transaction_stamp;
  unsigned long long queue_transaction_stamp;
  unsigned long long do_write_stamp;
  unsigned long long wctx_finish_stamp;
  unsigned long long aio_submit_stamp;
  unsigned long long aio_done_stamp;
  unsigned long long kv_submit_stamp;
  unsigned long long kv_committed_stamp;
  int aio_size;
  struct peers_info pi;
  struct delay_info di;
  unsigned long long reply_stamp;
  __u64 wb;
  __u64 rb;
  __u64 m_pool;
  __u32 m_seed;
};

typedef struct VarLocation {
  int reg;
  int offset;
  bool stack;
#ifndef BPF_KERNEL_SPACE
  VarLocation() {
    reg = 0;
    offset = 0;
    stack = false;
  }
#endif
} VarLocation;

struct Field {
  int offset;
  bool pointer;
};

#ifdef BPF_KERNEL_SPACE
struct VarField {
  VarLocation varloc;
  struct Field fields[8];
  int size;
};
#else
struct VarField {
  VarLocation varloc;
  std::vector<Field> fields;
};

struct VarField_Kernel {
  VarLocation varloc;
  struct Field fields[8];
  int size;
};
#endif

enum {
  l_bluestore_first = 732430,
  // space utilization stats
  //****************************************
  l_bluestore_allocated,
  l_bluestore_stored,
  l_bluestore_fragmentation,
  l_bluestore_alloc_unit,
  //****************************************

  // Update op processing state latencies
  //****************************************
  l_bluestore_state_prepare_lat,
  l_bluestore_state_aio_wait_lat,
  l_bluestore_state_io_done_lat,
  l_bluestore_state_kv_queued_lat,
  l_bluestore_state_kv_committing_lat,
  l_bluestore_state_kv_done_lat,
  l_bluestore_state_finishing_lat,
  l_bluestore_state_done_lat,

  l_bluestore_state_deferred_queued_lat,
  l_bluestore_state_deferred_aio_wait_lat,
  l_bluestore_state_deferred_cleanup_lat,

  l_bluestore_commit_lat,
  //****************************************

  // Update Transaction stats
  //****************************************
  l_bluestore_throttle_lat,
  l_bluestore_submit_lat,
  l_bluestore_txc,
  //****************************************

  // Read op stats
  //****************************************
  l_bluestore_read_onode_meta_lat,
  l_bluestore_read_wait_aio_lat,
  l_bluestore_csum_lat,
  l_bluestore_read_eio,
  l_bluestore_reads_with_retries,
  l_bluestore_read_lat,
  //****************************************

  // kv_thread latencies
  //****************************************
  l_bluestore_kv_flush_lat,
  l_bluestore_kv_commit_lat,
  l_bluestore_kv_sync_lat,
  l_bluestore_kv_final_lat,
  //****************************************

  // write op stats
  //****************************************
  l_bluestore_write_big,
  l_bluestore_write_big_bytes,
  l_bluestore_write_big_blobs,
  l_bluestore_write_big_deferred,

  l_bluestore_write_small,
  l_bluestore_write_small_bytes,
  l_bluestore_write_small_unused,
  l_bluestore_write_small_pre_read,

  l_bluestore_write_pad_bytes,
  l_bluestore_write_penalty_read_ops,
  l_bluestore_write_new,

  l_bluestore_issued_deferred_writes,
  l_bluestore_issued_deferred_write_bytes,
  l_bluestore_submitted_deferred_writes,
  l_bluestore_submitted_deferred_write_bytes,

  l_bluestore_write_big_skipped_blobs,
  l_bluestore_write_big_skipped_bytes,
  l_bluestore_write_small_skipped,
  l_bluestore_write_small_skipped_bytes,
  //****************************************

  // compressions stats
  //****************************************
  l_bluestore_compressed,
  l_bluestore_compressed_allocated,
  l_bluestore_compressed_original,
  l_bluestore_compress_lat,
  l_bluestore_decompress_lat,
  l_bluestore_compress_success_count,
  l_bluestore_compress_rejected_count,
  //****************************************

  // onode cache stats
  //****************************************
  l_bluestore_onodes,
  l_bluestore_pinned_onodes,
  l_bluestore_onode_hits,
  l_bluestore_onode_misses,
  l_bluestore_onode_shard_hits,
  l_bluestore_onode_shard_misses,
  l_bluestore_extents,
  l_bluestore_blobs,
  //****************************************

  // buffer cache stats
  //****************************************
  l_bluestore_buffers,
  l_bluestore_buffer_bytes,
  l_bluestore_buffer_hit_bytes,
  l_bluestore_buffer_miss_bytes,
  //****************************************

  // internal stats
  //****************************************
  l_bluestore_onode_reshard,
  l_bluestore_blob_split,
  l_bluestore_extent_compress,
  l_bluestore_gc_merged,
  //****************************************

  // misc
  //****************************************
  l_bluestore_omap_iterator_count,
  l_bluestore_omap_rmkeys_count,
  l_bluestore_omap_rmkey_ranges_count,
  //****************************************

  // other client ops latencies
  //****************************************
  l_bluestore_omap_seek_to_first_lat,
  l_bluestore_omap_upper_bound_lat,
  l_bluestore_omap_lower_bound_lat,
  l_bluestore_omap_next_lat,
  l_bluestore_omap_get_keys_lat,
  l_bluestore_omap_get_values_lat,
  l_bluestore_omap_clear_lat,
  l_bluestore_clist_lat,
  l_bluestore_remove_lat,
  l_bluestore_truncate_lat,
  //****************************************

  // allocation stats
  //****************************************
  l_bluestore_allocate_hist,
  //****************************************
  l_bluestore_last
};



#endif
