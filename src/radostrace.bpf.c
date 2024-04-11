#define BPF_KERNEL_SPACE

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <stdbool.h>
#include <string.h>

#include "bpf_osd_types.h"
#include "bpf_utils.h"
char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct client_op_k {
  __u64 cid;
  __u64 tid;
};

struct client_op_v {
  __u64 cid;
  __u64 tid;
  __u16 op_type;
  __u64 sent_stamp;
  __u64 finish_stamp;
  __u32 target_osd;
  //TODO peer OSDs
  //__u64 m_pool;
  //__u64 m_seed;
  //__u64 wb;
  //__u64 rb;
  //__u64 offset;
  //TODO object id;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct client_op_k);
  __type(value, struct client_op_v);
  __uint(max_entries, 8192);
} ops SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, int);
  __type(value, struct VarField);
  __uint(max_entries, 8192);
} hprobes SEC(".maps");

SEC("uprobe")
int uprobe_send_op(struct pt_regs *ctx) {
  int varid = 0;
  struct client_op_k key;
  memset(&key, 0, sizeof(key));
  // read tid
  struct VarField *vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (NULL != vf) {
    __u64 v = 0;
    v = fetch_register(ctx, vf->varloc.reg);
    __u64 tid_addr = fetch_var_member_addr(v, vf);
    bpf_probe_read_user(&key.tid, sizeof(key.tid), (void *)tid_addr);
    bpf_printk("uprobe_send_op got tid %lld\n", key.tid);
  } else {
    bpf_printk("uprobe_send_op got NULL vf at varid %d\n", varid);
  }

  // read client id
  // 
  //
  struct client_op_v val;
  val.sent_stamp = bpf_ktime_get_boot_ns();
  val.tid = key.tid;

}

SEC("uprobe")
int uprobe_finish_op(struct pt_regs *ctx) {
  int varid = 10;
  struct client_op_k key;
  memset(&key, 0, sizeof(key));
  // read tid
  struct VarField *vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (NULL != vf) {
    __u64 v = 0;
    v = fetch_register(ctx, vf->varloc.reg);
    __u64 tid_addr = fetch_var_member_addr(v, vf);
    bpf_probe_read_user(&key.tid, sizeof(key.tid), (void *)tid_addr);
    bpf_printk("uprobe_finish_op got tid %lld\n", key.tid);
  } else {
    bpf_printk("uprobe_finish_op got NULL vf at varid %d\n", varid);
  }
}

