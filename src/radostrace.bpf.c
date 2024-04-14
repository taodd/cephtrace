#define BPF_KERNEL_SPACE

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <stdbool.h>
#include <string.h>

#include "bpf_ceph_types.h"
#include "bpf_utils.h"
char LICENSE[] SEC("license") = "Dual BSD/GPL";

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
  bpf_printk("Entered uprobe_send_op\n");
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
  ++varid;
  vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (NULL != vf) {
    __u64 v = 0;
    v = fetch_register(ctx, vf->varloc.reg);
    __u64 cid_addr = fetch_var_member_addr(v, vf);
    bpf_probe_read_user(&key.cid, sizeof(key.cid), (void *)cid_addr);
    bpf_printk("uprobe_send_op got client id %lld\n", key.cid);
  } else {
    bpf_printk("uprobe_send_op got NULL vf at varid %d\n", varid);
  }

  struct client_op_v val;
  val.sent_stamp = bpf_ktime_get_boot_ns();
  val.tid = key.tid;
  val.cid = key.cid;
  val.op_type = 0; //TODO
  // read osd id
  ++varid;
  vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (NULL != vf) {
    __u64 v = 0;
    v = fetch_register(ctx, vf->varloc.reg);
    __u64 osd_addr = fetch_var_member_addr(v, vf);
    bpf_probe_read_user(&val.target_osd, sizeof(val.target_osd), (void *)osd_addr);
    bpf_printk("uprobe_send_op got osd id %lld\n", val.target_osd);
  } else {
    bpf_printk("uprobe_send_op got NULL vf at varid %d\n", varid);
  }


  bpf_map_update_elem(&ops, &key, &val, 0);
  return 0;
}

SEC("uprobe")
int uprobe_finish_op(struct pt_regs *ctx) {
  bpf_printk("Entered uprobe_finish_op\n");
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

  // read client id
  ++varid;
  vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (NULL != vf) {
    __u64 v = 0;
    v = fetch_register(ctx, vf->varloc.reg);
    __u64 cid_addr = fetch_var_member_addr(v, vf);
    bpf_probe_read_user(&key.cid, sizeof(key.cid), (void *)cid_addr);
    bpf_printk("uprobe_finish_op got client id %lld\n", key.cid);
  } else {
    bpf_printk("uprobe_finish_op got NULL vf at varid %d\n", varid);
  }

  struct client_op_v *opv = bpf_map_lookup_elem(&ops, &key);

  if (NULL == opv) {
    bpf_printk("uprobe_finish_op, no previous send_op info, client id %lld, tid %lld\n", key.cid, key.tid);
    return 0;
  }
  opv->finish_stamp = bpf_ktime_get_boot_ns();
  opv->pid = get_pid();
  // submit to ringbuf
  struct client_op_v *e = bpf_ringbuf_reserve(&rb, sizeof(struct op_v), 0);
  if (NULL == e) {
    return 0;
  }
  *e = *opv;
  bpf_ringbuf_submit(e, 0);

  bpf_map_delete_elem(&ops, &key);
  
  return 0;
}

