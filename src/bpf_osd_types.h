#ifndef BPF_OSD_TYPES_H
#define BPF_OSD_TYPES_H

#define MSG_OSD_REPOP 112
#define MSG_OSD_REPOPREPLY 113

#define MSG_OSD_OP 42
#define MSG_OSD_OPREPLY 43
 
static const __u8 flag_queued_for_pg=1 << 0;
static const __u8 flag_reached_pg =  1 << 1;
static const __u8 flag_delayed =     1 << 2;
static const __u8 flag_started =     1 << 3;
static const __u8 flag_sub_op_sent = 1 << 4;
static const __u8 flag_commit_sent = 1 << 5;

struct op_k {
  __u32 pid;    // process id
  __u64 owner;  // client id
  __u64 tid;    // request id from the client
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
  unsigned long long data_submit_stamp;
  unsigned long long data_committed_stamp;
  unsigned long long kv_submit_stamp;
  unsigned long long kv_committed_stamp;
  struct peers_info pi;
  struct delay_info di;
  unsigned long long reply_stamp;
  __u64 wb;
  __u64 rb;
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

#endif
