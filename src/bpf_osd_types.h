#ifndef BPF_OSD_TYPES_H
#define BPF_OSD_TYPES_H

struct op_k {
  __u32 pid; //process id
  __u64 owner; //client id
  __u64 tid;   //request id from the client
};

struct op_v {
  __u32 pid;
  unsigned long long owner;
  unsigned long long tid;
  unsigned long long recv_stamp;
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
  unsigned long long reply_stamp;
  __u64 wb;
  __u64 rb;
};

typedef struct VarLocation {
    int reg;
    int offset;
    bool stack;
#ifndef BPF_KERNEL_SPACE
    VarLocation() { reg=0; offset=0; stack=false; }
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
