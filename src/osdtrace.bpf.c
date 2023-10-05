#define BPF_KERNEL_SPACE

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <stdbool.h>
#include <string.h>

#include "bpf_osd_types.h"
// Reminding:  Use "swtich" statement in the bpf program might cause issues

// TODO: performance improvement: We can avoid fetching the common sturct multiple times for different var

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct op_k);
  __type(value, struct op_v);
  __uint(max_entries, 8192);
} ops SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u64);
  __type(value, struct op_k);
  __uint(max_entries, 128);
} ptid_opk SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct ctx_k);
  __type(value, struct op_k);
  __uint(max_entries, 128);
} ctx_opk SEC(".maps");

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

struct utime_t {
  __u32 sec;
  __u32 nsec;
};

struct timespec64 {
  __u64 tv_sec; /* seconds */
  long tv_nsec; /* nanoseconds */
};

static __always_inline __u64 to_nsec(struct utime_t *ut) {
  return (__u64)ut->sec * 1000000000ull + (__u64)ut->nsec;
}

__u32 get_pid() {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 pid = pid_tgid >> 32;
  return pid;
}

__u32 get_tid() {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 tid = (__u32)pid_tgid;
  return tid;
}

// currently only work for x86_64 arch
__u64 fetch_register(const struct pt_regs *const ctx, int reg) {
  __u64 v = 0;
  if (reg == 4)
    v = ctx->rsi;
  else if (reg == 5)
    v = ctx->rdi;
  else if (reg == 6)
    v = ctx->rbp;
  else if (reg == 7)
    v = ctx->rsp;
  else if (reg == 8)
    v = ctx->r8;
  else if (reg == 9)
    v = ctx->r9;
  else if (reg == 0)
    v = ctx->rax;
  else if (reg == 1)
    v = ctx->rdx;
  else if (reg == 2)
    v = ctx->rcx;
  else if (reg == 3)
    v = ctx->rbx;
  else {
    bpf_printk("unexpected register used\n");
  }
  return v;

  /* switch case is not supported well by eBPF, we'll run into  unable to
  deference modified ctx error switch (reg) { case 6: v = ctx->rbp; break; case
  7: v = ctx->rsp; break; case 0: v = ctx->rax; break; case 1: v =
  PT_REGS_PARM3(ctx); //rdx break; case 2: v = PT_REGS_PARM4(ctx); //rcx break;
      case 3:
          v = ctx->rbx;
          break;
      case 4:
          v = PT_REGS_PARM2(ctx); //rsi
          break;
      case 5:
          v = PT_REGS_PARM1(ctx); //rdi
          break;
      case 8:
          v = PT_REGS_PARM5(ctx); //r8
          break;
      case 9:
          v = ctx->r9;
          break;
      default:
          break;
  }
  */
  return v;
}

// deal with member dereference vf->size > 1
__u64 fetch_var_member_addr(__u64 cur_addr, struct VarField *vf) {
  if (vf == NULL) return 0;
  //__u64 cur_addr = fetch_register(ctx, vf->varloc.reg);
  if (cur_addr == 0) return 0;
  // special handling for the first member
  __u64 tmpaddr;
  if (vf->varloc.stack) {
    cur_addr += vf->varloc.offset;
    if (vf->fields[1].pointer) {
      bpf_probe_read_user(&tmpaddr, sizeof(tmpaddr), (void *)cur_addr);
      cur_addr = tmpaddr;
    }
  }
  cur_addr += vf->fields[1].offset;

  if (2 >= vf->size) return cur_addr;
  if (vf->fields[2].pointer) {
    bpf_probe_read_user(&tmpaddr, sizeof(tmpaddr), (void *)cur_addr);
    cur_addr = tmpaddr + vf->fields[2].offset;
  } else {
    cur_addr += vf->fields[2].offset;
  }

  if (3 >= vf->size) return cur_addr;
  if (vf->fields[3].pointer) {
    bpf_probe_read_user(&tmpaddr, sizeof(tmpaddr), (void *)cur_addr);
    cur_addr = tmpaddr + vf->fields[3].offset;
  } else {
    cur_addr += vf->fields[3].offset;
  }

  if (4 >= vf->size) return cur_addr;
  if (vf->fields[4].pointer) {
    bpf_probe_read_user(&tmpaddr, sizeof(tmpaddr), (void *)cur_addr);
    cur_addr = tmpaddr + vf->fields[4].offset;
  } else {
    cur_addr += vf->fields[4].offset;
  }

  if (5 >= vf->size) return cur_addr;
  if (vf->fields[5].pointer) {
    bpf_probe_read_user(&tmpaddr, sizeof(tmpaddr), (void *)cur_addr);
    cur_addr = tmpaddr + vf->fields[5].offset;
  } else {
    cur_addr += vf->fields[5].offset;
  }

  return cur_addr;
}

int print_vf(struct VarField *vf) {
  if (vf == NULL) return 0;
  bpf_printk("reg %d offset %d onstack %d\n", vf->varloc.reg, vf->varloc.offset,
             vf->varloc.stack);
  if (1 >= vf->size) return 0;
  bpf_printk("field 1 offset %d, pointer %d", vf->fields[1].offset,
             vf->fields[1].pointer);
  if (2 >= vf->size) return 0;
  bpf_printk("field 2 offset %d, pointer %d", vf->fields[2].offset,
             vf->fields[2].pointer);
  if (3 >= vf->size) return 0;
  bpf_printk("field 3 offset %d, pointer %d", vf->fields[3].offset,
             vf->fields[3].pointer);
  if (4 >= vf->size) return 0;
  bpf_printk("field 4 offset %d, pointer %d", vf->fields[4].offset,
             vf->fields[4].pointer);
  if (5 >= vf->size) return 0;
  bpf_printk("field 5 offset %d, pointer %d", vf->fields[5].offset,
             vf->fields[5].pointer);
  return 0;
}

SEC("uprobe")
int uprobe_enqueue_op(struct pt_regs *ctx) {
  int varid = 0;
  struct op_k key;
  memset(&key, 0, sizeof(key));
  // read op type, skip if it's not osd_op type
  __u16 op_type = 0;
  struct VarField *vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (NULL != vf) {
    __u64 v = 0;
    v = fetch_register(ctx, vf->varloc.reg);
    __u64 op_type_addr = fetch_var_member_addr(v, vf);
    bpf_probe_read_user(&op_type, sizeof(op_type), (void *)op_type_addr);
  } else {
    bpf_printk("uprobe_enqueue_op got NULL vf at varid %d\n", varid);
  }
  if (op_type != MSG_OSD_OP) {
    bpf_printk("uprobe_enqueue_op got a non osdop/osdrepop %d, ignore\n", op_type);
    return 0;
  }

  // read _num
  varid++;
  vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (NULL != vf) {
    // print_vf(vf);
    __u64 v = 0;
    v = fetch_register(ctx, vf->varloc.reg);
    __u64 num_addr = fetch_var_member_addr(v, vf);
    bpf_probe_read_user(&key.owner, sizeof(key.owner), (void *)num_addr);
  } else {
    bpf_printk("uprobe_enqueue_op got NULL vf at varid %d\n", varid);
    return 0;
  }

  // read tid
  ++varid;
  vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (NULL != vf) {
    __u64 v = 0;
    v = fetch_register(ctx, vf->varloc.reg);
    __u64 tid_addr = fetch_var_member_addr(v, vf);
    bpf_probe_read_user(&key.tid, sizeof(key.tid), (void *)tid_addr);
  } else {
    bpf_printk("uprobe_enqueue_op got NULL vf at varid %d\n", varid);
    return 0;
  }
  bpf_printk("enqueue_op client %lld tid %lld\n", key.owner, key.tid);

  key.pid = get_pid();
  struct op_v value;
  memset(&value, 0, sizeof(value));
  // ktime_get_real_ts64 can't be called
  /*struct timespec64 *ts;
  ktime_get_real_ts64(ts);
  __u64 now_sec = ts->tv_sec;
  __u64 now_nsec = ts->tv_nsec;*/

  value.enqueue_stamp = bpf_ktime_get_boot_ns();
  value.pid = key.pid;
  value.tid = key.tid;
  value.owner = key.owner;
  value.op_type = op_type;
  //initialize peer id to -1
  value.pi.peer1 = -1;
  value.pi.peer2 = -1;
  struct utime_t stamp;

  // Set recv_stamp
  ++varid;
  vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (NULL != vf) {
    __u64 v = 0;
    v = fetch_register(ctx, vf->varloc.reg);
    __u64 recv_stamp_addr = fetch_var_member_addr(v, vf);
    bpf_probe_read_user(&stamp.sec, sizeof(stamp.sec), (void *)recv_stamp_addr);
    bpf_probe_read_user(&stamp.nsec, sizeof(stamp.nsec),
                        (void *)(recv_stamp_addr + 4));
    value.recv_stamp = to_nsec(&stamp);
  } else {
    bpf_printk("uprobe_enqueue_op got NULL vf at varid %d\n", varid);
    return 0;
  }
  bpf_printk("enqueue_op recv_stamp %lld\n", value.recv_stamp);

  // Set throttle_stamp
  ++varid;
  vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (NULL != vf) {
    __u64 v = 0;
    v = fetch_register(ctx, vf->varloc.reg);
    __u64 throttle_stamp_addr = fetch_var_member_addr(v, vf);
    bpf_probe_read_user(&stamp.sec, sizeof(stamp.sec), (void *)throttle_stamp_addr);
    bpf_probe_read_user(&stamp.nsec, sizeof(stamp.nsec),
                        (void *)(throttle_stamp_addr + 4));
    value.throttle_stamp = to_nsec(&stamp);
  } else {
    bpf_printk("uprobe_enqueue_op got NULL vf at varid %d\n", varid);
    return 0;
  }
  bpf_printk("enqueue_op throttle_stamp %lld\n", value.throttle_stamp);

  // Set recv_complete_stamp
  ++varid;
  vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (NULL != vf) {
    __u64 v = 0;
    v = fetch_register(ctx, vf->varloc.reg);
    __u64 recv_complete_stamp_addr = fetch_var_member_addr(v, vf);
    bpf_probe_read_user(&stamp.sec, sizeof(stamp.sec),
                        (void *)recv_complete_stamp_addr);
    bpf_probe_read_user(&stamp.nsec, sizeof(stamp.nsec),
                        (void *)(recv_complete_stamp_addr + 4));
    value.recv_complete_stamp = to_nsec(&stamp);
  } else {
    bpf_printk("uprobe_enqueue_op got NULL vf at varid %d\n", varid);
    return 0;
  }
  bpf_printk("enqueue_op recv_complete_stamp %lld\n",
             value.recv_complete_stamp);

  // Set dispatch_stamp
  ++varid;
  vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (NULL != vf) {
    __u64 v = 0;
    v = fetch_register(ctx, vf->varloc.reg);
    __u64 dispatch_stamp_addr = fetch_var_member_addr(v, vf);
    bpf_probe_read_user(&stamp.sec, sizeof(stamp.sec),
                        (void *)dispatch_stamp_addr);
    bpf_probe_read_user(&stamp.nsec, sizeof(stamp.nsec),
                        (void *)(dispatch_stamp_addr + 4));
    value.dispatch_stamp = to_nsec(&stamp);
  } else {
    bpf_printk("uprobe_enqueue_op got NULL vf at varid %d\n", varid);
    return 0;
  }
  bpf_printk("enqueue_op dispatch_stamp %lld\n", value.dispatch_stamp);

  // Set m_pool
  ++varid;
  vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (NULL != vf) {
    __u64 v = 0;
    v = fetch_register(ctx, vf->varloc.reg);
    __u64 m_pool_addr = fetch_var_member_addr(v, vf);
    __u64 m_pool;
    bpf_probe_read_user(&m_pool, sizeof(m_pool),(void *)m_pool_addr);
    value.m_pool = m_pool;
  } else {
    bpf_printk("uprobe_enqueue_op got NULL vf at varid %d\n", varid);
    return 0;
  }
  //Set m_seed
  ++varid;
  vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (NULL != vf) {
    __u64 v = 0;
    v = fetch_register(ctx, vf->varloc.reg);
    __u64 m_seed_addr = fetch_var_member_addr(v, vf);
    __u32 m_seed;
    bpf_probe_read_user(&m_seed, sizeof(m_seed),(void *)m_seed_addr);
    value.m_seed = m_seed;
  } else {
    bpf_printk("uprobe_enqueue_op got NULL vf at varid %d\n", varid);
    return 0;
  }

  bpf_map_update_elem(&ops, &key, &value, 0);
  return 0;
}

SEC("uprobe")
int uprobe_dequeue_op(struct pt_regs *ctx) {
  bpf_printk("Entered into uprobe_dequeue_op\n");

  struct op_k key;
  memset(&key, 0, sizeof(key));
  int varid = 10;
  // read op type, skip if it's not osd_op type
  __u16 op_type = 0;
  struct VarField *vf = bpf_map_lookup_elem(&hprobes, &varid);

  if (NULL != vf) {
    __u64 v = 0;
    v = fetch_register(ctx, vf->varloc.reg);
    __u64 op_type_addr = fetch_var_member_addr(v, vf);
    bpf_probe_read_user(&op_type, sizeof(op_type), (void *)op_type_addr);
  } else {
    bpf_printk("uprobe_dequeue_op got NULL vf at varid %d\n", varid);
  }
  if (op_type != MSG_OSD_OP) {
    bpf_printk("uprobe_dequeue_op got non osd op or repop type %d, ignore\n", op_type);
    return 0;
  }

  // read num
  ++varid;
  vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (NULL != vf) {
    __u64 v = 0;
    v = fetch_register(ctx, vf->varloc.reg);
    __u64 num_addr = fetch_var_member_addr(v, vf);
    bpf_probe_read_user(&key.owner, sizeof(key.owner), (void *)num_addr);
  } else {
    bpf_printk("uprobe_dequeue_op got NULL vf at varid %d\n", varid);
  }
  // read tid
  ++varid;
  vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (NULL != vf) {
    __u64 v = 0;
    v = fetch_register(ctx, vf->varloc.reg);
    __u64 tid_addr = fetch_var_member_addr(v, vf);
    bpf_probe_read_user(&key.tid, sizeof(key.tid), (void *)tid_addr);
  } else {
    bpf_printk("uprobe_dequeue_op got NULL vf at varid %d\n", varid);
    return 0;
  }
  key.pid = get_pid();

  bpf_printk("Entered into uprobe_dequeue_op key owner %lld, tid %lld\n",
             key.owner, key.tid);

  struct op_v *vp = bpf_map_lookup_elem(&ops, &key);
  if (NULL != vp) {
    if (vp->dequeue_stamp == 0)
      vp->dequeue_stamp = bpf_ktime_get_boot_ns();

    __u64 ptid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&ptid_opk, &ptid, &key, 0);
  } else {
    bpf_printk("uprobe_dequeue_op, no previous enqueue_op info, owner %lld, tid %lld\n", key.owner, key.tid);
    return 0;
  }
  return 0;
}
//Not attached
SEC("uprobe")
int uprobe_execute_ctx(struct pt_regs *ctx) {
  bpf_printk("Entered into uprobe_execute_ctx\n");

  int varid = 20;
  struct op_k key;
  memset(&key, 0, sizeof(key));
  // read num
  struct VarField *vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (NULL != vf) {
    __u64 v = 0;
    v = fetch_register(ctx, vf->varloc.reg);
    __u64 num_addr = fetch_var_member_addr(v, vf);
    bpf_probe_read_user(&key.owner, sizeof(key.owner), (void *)num_addr);
  } else {
    bpf_printk("uprobe_execute_ctx got NULL vf at varid %d\n", varid);
  }
  // read tid
  ++varid;
  vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (NULL != vf) {
    __u64 v = 0;
    v = fetch_register(ctx, vf->varloc.reg);
    __u64 tid_addr = fetch_var_member_addr(v, vf);
    bpf_probe_read_user(&key.tid, sizeof(key.tid), (void *)tid_addr);
  } else {
    bpf_printk("uprobe_execute_ctx got NULL vf at varid %d\n", varid);
    return 0;
  }
  key.pid = get_pid();

  bpf_printk("Entered into uprobe_execute_ctx key owner %lld, tid %lld \n",
             key.owner, key.tid);

  struct op_v *vp = bpf_map_lookup_elem(&ops, &key);
  if (NULL != vp) {
    vp->execute_ctx_stamp = bpf_ktime_get_boot_ns();
  } else {
    bpf_printk(
        "uprobe_execute_ctx, no previous op info, owner %lld, tid %lld\n",
        key.owner, key.tid);
    return 0;
  }

  return 0;
}

//Not Attached
SEC("uprobe")
int uprobe_submit_transaction(struct pt_regs *ctx) {
  bpf_printk("Entered into uprobe_submit_transaction\n");

  int varid = 30;
  struct op_k key;
  memset(&key, 0, sizeof(key));
  // read num
  struct VarField *vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (NULL != vf) {
    __u64 v = 0;
    v = fetch_register(ctx, vf->varloc.reg);
    __u64 num_addr = fetch_var_member_addr(v, vf);
    bpf_probe_read_user(&key.owner, sizeof(key.owner), (void *)num_addr);
  } else {
    bpf_printk("uprobe_submit_transaction got NULL vf at varid %d\n", varid);
  }
  // read tid
  ++varid;
  vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (NULL != vf) {
    __u64 v = 0;
    v = fetch_register(ctx, vf->varloc.reg);
    __u64 tid_addr = fetch_var_member_addr(v, vf);
    bpf_probe_read_user(&key.tid, sizeof(key.tid), (void *)tid_addr);
  } else {
    bpf_printk("uprobe_submit_transaction got NULL vf at varid %d\n", varid);
    return 0;
  }

  key.pid = get_pid();

  // TODO ReplicatedBackend::submit_transaction can get the objectid

  struct op_v *vp = bpf_map_lookup_elem(&ops, &key);

  bpf_printk(
      "Entered into uprobe_submit_transaction key owner %lld, tid %lld, op "
      "%llx\n",
      key.owner, key.tid, vp);
  if (NULL != vp) {
    vp->submit_transaction_stamp = bpf_ktime_get_boot_ns();
    __u64 ptid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&ptid_opk, &ptid, &key, 0);
  } else {
    bpf_printk(
        "uprobe_submit_transaction, no previous op info, owner %lld, tid "
        "%lld\n",
        key.owner, key.tid);
  }
  return 0;
}

// BlueStore::queue_transactions
SEC("uprobe")
int uprobe_queue_transactions(struct pt_regs *ctx) {
  bpf_printk("Entered into uprobe_queue_transactions\n");
  __u64 ptid = bpf_get_current_pid_tgid();
  struct op_k *key = bpf_map_lookup_elem(&ptid_opk, &ptid);

  if (NULL != key) {
    struct op_v *vp = bpf_map_lookup_elem(&ops, key);
    if (NULL != vp) {
      vp->queue_transaction_stamp = bpf_ktime_get_boot_ns();
    } else {
      bpf_printk(
          "uprobe_queue_transaction, no previous key matched owner %lld, tid "
          "%lld\n",
          key->owner, key->tid);
    }
  } else {
    bpf_printk("uprobe_queue_transaction, no previous tid matched %d\n", tid);
  }
  return 0;
}

//Not attached
// BlueStore::_do_write
SEC("uprobe")
int uprobe_do_write(struct pt_regs *ctx) {
  bpf_printk("Entered into uprobe_do_write\n");
  __u64 ptid = bpf_get_current_pid_tgid();
  struct op_k *key = bpf_map_lookup_elem(&ptid_opk, &ptid);
  if (NULL != key) {
    struct op_v *vp = bpf_map_lookup_elem(&ops, key);
    if (NULL != vp) {
      vp->do_write_stamp = bpf_ktime_get_boot_ns();
      // TODO offset and length
    } else {
      bpf_printk(
          "uprobe_do_write, no previous key matched owner %lld, tid %lld\n",
          key->owner, key->tid);
    }
  } else {
    bpf_printk("uprobe_do_write, no previous tid matched %d\n", tid);
  }
  return 0;
}

// BlueStore::_wctx_finish
// TODO attach to uprobe later
SEC("uprobe")
int uprobe_wctx_finish(struct pt_regs *ctx) {
  bpf_printk("Entered into uprobe_wctx_finish\n");
  __u64 ptid = bpf_get_current_pid_tgid();
  struct op_k *key = bpf_map_lookup_elem(&ptid_opk, &ptid);
  if (NULL != key) {
    struct op_v *vp = bpf_map_lookup_elem(&ops, key);
    if (NULL != vp) {
      vp->wctx_finish_stamp = bpf_ktime_get_boot_ns();
      // delete the item in ptid_opk and create a new item to ctx_opk
      bpf_map_delete_elem(&ptid_opk, &ptid); // this will need to be delayed to submit_batch
      // read ctx->osr->px->sequencer_id
      int varid = 60;
      struct VarField *vf = bpf_map_lookup_elem(&hprobes, &varid);
      if (vf == NULL) return 0;
      __u64 v = 0;
      v = fetch_register(ctx, vf->varloc.reg);
      __u64 seqid_addr = fetch_var_member_addr(v, vf);
      __u32 seqid = 0;
      bpf_probe_read_user(&seqid, sizeof(seqid), (void *)seqid_addr);

      //read ctx->start
      ++varid;
      vf = bpf_map_lookup_elem(&hprobes, &varid);
      if (vf == NULL) return 0;
      v = fetch_register(ctx, vf->varloc.reg);
      __u64 start_addr = fetch_var_member_addr(v, vf);
      __u64 start = 0;
      bpf_probe_read_user(&start, sizeof(start), (void *)start_addr);

      struct ctx_k ck;
      ck.seqid = seqid;
      ck.start_stamp = start; 
      ck.pid = get_pid(); 

      bpf_map_update_elem(&ctx_opk, &ck, key, 0);
      // TODO offset and length
    } else {
      bpf_printk(
          "uprobe_wctx_finish, no previous key matched owner %lld, tid %lld\n",
          key->owner, key->tid);
    }
  } else {
    bpf_printk("uprobe_wctx_finish, no previous tid matched %d\n", tid);
  }
  return 0;
}

// BlueStore::_txc_state_proc
SEC("uprobe")
int uprobe_txc_state_proc(struct pt_regs *ctx) {
  bpf_printk("Entered into uprobe_txc_state_proc\n");
  // read ctx->osr->px->sequencer_id
  int varid = 70;
  struct VarField *vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (vf == NULL) return 0;
  __u64 v = 0;
  v = fetch_register(ctx, vf->varloc.reg);
  __u64 seqid_addr = fetch_var_member_addr(v, vf);
  __u32 seqid = 0;
  bpf_probe_read_user(&seqid, sizeof(seqid), (void *)seqid_addr);

  //read ctx->start
  ++varid;
  vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (vf == NULL) return 0;
  v = fetch_register(ctx, vf->varloc.reg);
  __u64 start_addr = fetch_var_member_addr(v, vf);
  __u64 start = 0;
  bpf_probe_read_user(&start, sizeof(start), (void *)start_addr);

  struct ctx_k ck;
  ck.seqid = seqid;
  ck.start_stamp = start; 
  ck.pid = get_pid(); 
  struct op_k *key = bpf_map_lookup_elem(&ctx_opk, &ck);
  if (NULL == key) {
    bpf_printk("uprobe_txc_state_proc got NULL key at ck %lld %lld %lld\n", ck.seqid, ck.start_stamp, ck.pid);
    return 0;
  }
  // read ctx->state
  ++varid;
  vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (NULL == vf) return 0;
  v = fetch_register(ctx, vf->varloc.reg);
  __u64 state_addr = fetch_var_member_addr(v, vf);
  __u32 state = 0;
  bpf_probe_read_user(&state, sizeof(state), (void *)state_addr);
  struct op_v *vp = bpf_map_lookup_elem(&ops, key);
  if (NULL == vp) return 0;
  //read ctx->ioc->num_pending
  ++varid;
  vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (NULL == vf) return 0;
  v = fetch_register(ctx, vf->varloc.reg);
  if (state == 0) {  // STATE_PREPARE
    vp->aio_submit_stamp = bpf_ktime_get_boot_ns();
    __u64 pending_addr = fetch_var_member_addr(v, vf);
    int pending_num = 0;
    bpf_probe_read_user(&pending_num, sizeof(pending_num), (void *)pending_addr);
    vp->aio_size = pending_num;
    bpf_printk("uprobe_txc_state_proc owner %lld tid %lld aio_submit_stamp = %lld", key->owner, key->tid, vp->aio_submit_stamp);
  } else if (state == 1) {  // STATE_AIO_WAIT
    // until flushed can it be considered committed, not here.
    vp->aio_done_stamp = bpf_ktime_get_boot_ns();
    bpf_printk("uprobe_txc_state_proc owner %lld tid %lld aio_done_stamp = %lld", key->owner, key->tid, vp->aio_done_stamp);
  } else if (state == 2) {  // STATE_IO_DONE sending to kv queue
    vp->kv_submit_stamp = bpf_ktime_get_boot_ns();
    bpf_printk("uprobe_txc_state_proc owner %lld tid %lld kv_submit_stamp = %lld", key->owner, key->tid, vp->kv_submit_stamp);
  } else if (state == 4) {  // STATE_KV_SUBMITTED
    vp->kv_committed_stamp = bpf_ktime_get_boot_ns();
    bpf_printk("uprobe_txc_state_proc owner %lld tid %lld kv_committed_stamp = %lld", key->owner, key->tid, vp->kv_committed_stamp);
    // last stage of the ctx, delete it from the map
    bpf_map_delete_elem(&ctx_opk, &ck);
  }

  return 0;
}

//Not Attached
//BlueStore::_txc_apply_kv
/*SEC("uprobe")
int uprobe_txc_apply_kv(struct pt_regs *ctx) {
}*/

SEC("uprobe")
int uprobe_log_op_stats(struct pt_regs *ctx) {
  bpf_printk("Entered into uprobe_log_op_stats\n");
  int varid = 90;
  struct op_k key;
  memset(&key, 0, sizeof(key));
  // read num
  struct VarField *vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (NULL != vf) {
    __u64 v = 0;
    v = fetch_register(ctx, vf->varloc.reg);
    __u64 num_addr = fetch_var_member_addr(v, vf);
    bpf_probe_read_user(&key.owner, sizeof(key.owner), (void *)num_addr);
  } else {
    bpf_printk("uprobe_log_op_stats got NULL vf at varid %d\n", varid);
  }
  // read tid
  ++varid;
  vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (NULL != vf) {
    __u64 v = 0;
    v = fetch_register(ctx, vf->varloc.reg);
    __u64 tid_addr = fetch_var_member_addr(v, vf);
    bpf_probe_read_user(&key.tid, sizeof(key.tid), (void *)tid_addr);
  } else {
    bpf_printk("uprobe_log_op_stats got NULL vf at varid %d\n", varid);
    return 0;
  }
  key.pid = get_pid();

  struct op_v *vp = bpf_map_lookup_elem(&ops, &key);
  if (NULL != vp) {
    vp->reply_stamp = bpf_ktime_get_boot_ns();
    vp->wb = PT_REGS_PARM3(ctx);
    vp->rb = PT_REGS_PARM4(ctx);
    struct op_v *e = bpf_ringbuf_reserve(&rb, sizeof(struct op_v), 0);
    if (NULL == e) {
      return 0;
    }
    *e = *vp;
    bpf_ringbuf_submit(e, 0);
  } else {
    bpf_printk(
        "uprobe_log_op_stats, no previous op info, owner %lld, tid %lld\n",
        key.owner, key.tid);
  }
end:
  bpf_map_delete_elem(&ops, &key);
  return 0;
}

SEC("uprobe")
int uprobe_log_op_stats_v2(struct pt_regs *ctx) {
  bpf_printk("Entered into uprobe_log_op_stats v2\n");
  int varid = 90;
  struct op_v op;
  memset(&op, 0, sizeof(op));
  // read num
  struct VarField *vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (NULL != vf) {
    __u64 v = 0;
    v = fetch_register(ctx, vf->varloc.reg);
    __u64 num_addr = fetch_var_member_addr(v, vf);
    bpf_probe_read_user(&op.owner, sizeof(op.owner), (void *)num_addr);
  } else {
    bpf_printk("uprobe_log_op_stats_v2 got NULL vf at varid %d\n", varid);
  }
  // read tid
  ++varid;
  vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (NULL != vf) {
    __u64 v = 0;
    v = fetch_register(ctx, vf->varloc.reg);
    __u64 tid_addr = fetch_var_member_addr(v, vf);
    bpf_probe_read_user(&op.tid, sizeof(op.tid), (void *)tid_addr);
  } else {
    bpf_printk("uprobe_log_op_stats_v2 got NULL vf at varid %d\n", varid);
    return 0;
  }
  op.pid = get_pid();
  op.reply_stamp = bpf_ktime_get_boot_ns();
  ++varid;
  op.wb = PT_REGS_PARM3(ctx);
  ++varid;
  op.rb = PT_REGS_PARM4(ctx);
  //read recv_stamp
  ++varid;
  vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (NULL != vf) {
    __u64 v = 0;
    v = fetch_register(ctx, vf->varloc.reg);
    struct utime_t stamp;
    __u64 recv_stamp_addr = fetch_var_member_addr(v, vf);
    bpf_probe_read_user(&stamp.sec, sizeof(stamp.sec), (void *)recv_stamp_addr);
    bpf_probe_read_user(&stamp.nsec, sizeof(stamp.nsec),
                        (void *)(recv_stamp_addr + 4));
    op.recv_stamp = to_nsec(&stamp);
    /*if (op.recv_stamp == 0) { 
     * TODO around 0.01 percentile of the ops have recv_stamp==0
      bpf_printk("stamp.sec %lld, stamp.nsec %lld\n", stamp.sec, stamp.nsec);  
      bpf_printk("recv_stamp_addr %lld\n", recv_stamp_addr);
    }*/
  } else {
    bpf_printk("uprobe_log_op_stats_v2 got NULL vf at varid %d\n", varid);
    return 0;
  }
  //read op type 
  ++varid;
  vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (NULL != vf) {
    __u64 v = 0;
    v = fetch_register(ctx, vf->varloc.reg);
    __u64 op_type_addr = fetch_var_member_addr(v, vf);
    bpf_probe_read_user(&op.op_type, sizeof(op.op_type), (void *)op_type_addr);
  } else {
    bpf_printk("uprobe_log_op_stats_v2 got NULL vf at varid %d\n", varid);
    return 0;
  }
  bpf_printk(" log_op_stats_v2 client %lld tid %lld recv_stamp %lld ", op.owner, op.tid, op.recv_stamp);
  bpf_printk(" inb %lld outb %lld op type %lld\n",op.wb, op.rb, op.op_type);
  //submit the op
  struct op_v *e = bpf_ringbuf_reserve(&rb, sizeof(struct op_v), 0);
  if (NULL == e) {
    return 0;
  }
  *e = op;
  bpf_ringbuf_submit(e, 0);
  return 0;
}

SEC("uprobe")
int uprobe_generate_subop(struct pt_regs *ctx)
{
  bpf_printk("Entered into uprobe_generate_subop\n");
  int varid = 100;
  struct op_k key;
  memset(&key, 0, sizeof(key));
  // read num
  struct VarField *vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (NULL != vf) {
    __u64 v = 0;
    v = fetch_register(ctx, vf->varloc.reg);
    __u64 num_addr = fetch_var_member_addr(v, vf);
    bpf_probe_read_user(&key.owner, sizeof(key.owner), (void *)num_addr);
  } else {
    bpf_printk("uprobe_generate_subop got NULL vf at varid %d\n", varid);
  }
  // read tid
  ++varid;
  vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (NULL != vf) {
    __u64 v = 0;
    v = fetch_register(ctx, vf->varloc.reg);
    __u64 tid_addr = fetch_var_member_addr(v, vf);
    bpf_probe_read_user(&key.tid, sizeof(key.tid), (void *)tid_addr);
  } else {
    bpf_printk("uprobe_generate_subop got NULL vf at varid %d\n", varid);
    return 0;
  }
  key.pid = get_pid();

  struct op_v *vp = bpf_map_lookup_elem(&ops, &key);
  if (vp == NULL) {
    bpf_printk("uprobe_generate_subop got NULL vp for client %lld, tid %lld\n", key.owner, key.tid);
    return 0;
  }

  //read peer osd id
  ++varid;
  vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (NULL != vf) {
    __u64 v = 0;
    v = fetch_register(ctx, vf->varloc.reg);
    __u64 peer_addr = fetch_var_member_addr(v, vf);
    if (vp->pi.peer1 == -1) {
      bpf_probe_read_user(&vp->pi.peer1, sizeof(int), (void *)peer_addr);
    } else {
      bpf_probe_read_user(&vp->pi.peer2, sizeof(int), (void *)peer_addr);
    }
  } else {
    bpf_printk("uprobe_generate_subop got NULL vf at varid %d\n", varid);
    return 0;
  }
  //set sent stamp, just use the latter one
  vp->pi.sent_stamp = bpf_ktime_get_boot_ns();

  return 0;
}

SEC("uprobe")
int uprobe_do_repop_reply(struct pt_regs *ctx)
{
  bpf_printk("Entered into uprobe_do_repop_reply\n");
  int varid = 110;
  struct op_k key;
  memset(&key, 0, sizeof(key));
  // read num
  struct VarField *vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (NULL != vf) {
    __u64 v = 0;
    v = fetch_register(ctx, vf->varloc.reg);
    __u64 num_addr = fetch_var_member_addr(v, vf);
    bpf_probe_read_user(&key.owner, sizeof(key.owner), (void *)num_addr);
  } else {
    bpf_printk("uprobe_do_repop_reply got NULL vf at varid %d\n", varid);
  }
  // read tid
  ++varid;
  vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (NULL != vf) {
    __u64 v = 0;
    v = fetch_register(ctx, vf->varloc.reg);
    __u64 tid_addr = fetch_var_member_addr(v, vf);
    bpf_probe_read_user(&key.tid, sizeof(key.tid), (void *)tid_addr);
  } else {
    bpf_printk("uprobe_do_repop_reply got NULL vf at varid %d\n", varid);
    return 0;
  }
  key.pid = get_pid();

  // read source osdid
  int osdid = -1;
  ++varid;
  vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (NULL != vf) {
    __u64 v = 0;
    v = fetch_register(ctx, vf->varloc.reg);
    __u64 osdid_addr = fetch_var_member_addr(v, vf);
    bpf_probe_read_user(&osdid, sizeof(osdid), (void *)osdid_addr);
  } else {
    bpf_printk("uprobe_do_repop_reply got NULL vf at varid %d\n", varid);
    return 0;
  }

  struct op_v *vp = bpf_map_lookup_elem(&ops, &key);
  if (NULL != vp) {
    if (osdid == vp->pi.peer1)
      vp->pi.recv_stamp1 = bpf_ktime_get_boot_ns();
    else if (osdid == vp->pi.peer2)
      vp->pi.recv_stamp2 = bpf_ktime_get_boot_ns();
  } else {
    bpf_printk("uprobe_do_repop_reply unable to get op_v for client %lld, tid %lld\n", key.owner, key.tid);  
  }
  return 0;
}

SEC("uprobe")
int uprobe_mark_flag_point_string(struct pt_regs *ctx)
{
  bpf_printk("Entered into mark_flag_point_string\n");
  int varid = 120;
  // read flag
  __u8 flag = PT_REGS_PARM2(ctx);
  bpf_printk("flag is %d\n", flag);
  if(!(flag & flag_delayed))
    return 0;
  struct op_k key;
  memset(&key, 0, sizeof(key));
  // read num
  ++varid;
  struct VarField *vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (NULL != vf) {
    __u64 v = 0;
    v = fetch_register(ctx, vf->varloc.reg);
    __u64 num_addr = fetch_var_member_addr(v, vf);
    bpf_probe_read_user(&key.owner, sizeof(key.owner), (void *)num_addr);
  } else {
    bpf_printk("uprobe_mark_flag_point_string got NULL vf at varid %d\n", varid);
  }
  // read tid
  ++varid;
  vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (NULL != vf) {
    __u64 v = 0;
    v = fetch_register(ctx, vf->varloc.reg);
    __u64 tid_addr = fetch_var_member_addr(v, vf);
    bpf_probe_read_user(&key.tid, sizeof(key.tid), (void *)tid_addr);
  } else {
    bpf_printk("uprobe_mark_flag_point_string got NULL vf at varid %d\n", varid);
    return 0;
  }
  key.pid = get_pid();

  struct op_v *vp = bpf_map_lookup_elem(&ops, &key);
  if (vp == NULL) 
    return 0;

  // read string length
  ++varid;
  vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (NULL == vf)
    return 0;
  __u64 v = 0;
  v = fetch_register(ctx, vf->varloc.reg);
  __u64 strlen_addr = fetch_var_member_addr(v, vf);
  __u32 len = 0;
  bpf_probe_read_user(&len, sizeof(len), (void *)strlen_addr);
  
  __u32 idx = vp->di.cnt;

  // read string buf
  ++varid;
  vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (NULL == vf)
    return 0;
  v = fetch_register(ctx, vf->varloc.reg);
  __u64 m_local_buf_addr = fetch_var_member_addr(v, vf);
  __u64 str_addr;
  bpf_probe_read_user(&str_addr, sizeof(str_addr), (void *)m_local_buf_addr);

  if (idx >= 5 || len >= 32)
    return 0;
  bpf_probe_read_user(vp->di.delays[idx], len, (void *)str_addr);
  vp->di.cnt++;
  return 0;
}

SEC("uprobe")
int uprobe_log_latency(struct pt_regs *ctx)
{
  bpf_printk("Entered into log_latency\n");
  int varid = 130;
  struct bluestore_lat_v bsl;
  // read idx
  bsl.idx = PT_REGS_PARM3(ctx);

  //read l.__r
  ++varid;
  struct VarField *vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (NULL == vf)
    return 0;
  __u64 v = fetch_register(ctx, vf->varloc.reg);
  __u64 r_addr = fetch_var_member_addr(v, vf);
  bpf_probe_read_user(&bsl.lat, sizeof(__u64), (void *)r_addr);

  //set pid
  bsl.pid = get_pid(); 

  //submit the bs latency
  struct bluestore_lat_v *e = bpf_ringbuf_reserve(&rb, sizeof(struct bluestore_lat_v), 0);
  if (NULL == e) {
    return 0;
  }
  *e = bsl;
  bpf_ringbuf_submit(e, 0);

  return 0;
}
/*
SEC("uprobe")
int uprobe_log_subop_stats(struct pt_regs *ctx)
{
  bpf_printk("Entered into log_subop_stats\n");
  int varid = 140;
  struct op_v op;
  memset(&op, 0, sizeof(op));
  // read num
  struct VarField *vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (NULL != vf) {
    __u64 v = 0;
    v = fetch_register(ctx, vf->varloc.reg);
    __u64 num_addr = fetch_var_member_addr(v, vf);
    bpf_probe_read_user(&op.owner, sizeof(op.owner), (void *)num_addr);
  } else {
    bpf_printk("uprobe_log_op_stats_v2 got NULL vf at varid %d\n", varid);
  }
  // read tid
  ++varid;
  vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (NULL != vf) {
    __u64 v = 0;
    v = fetch_register(ctx, vf->varloc.reg);
    __u64 tid_addr = fetch_var_member_addr(v, vf);
    bpf_probe_read_user(&op.tid, sizeof(op.tid), (void *)tid_addr);
  } else {
    bpf_printk("uprobe_log_op_stats_v2 got NULL vf at varid %d\n", varid);
    return 0;
  }
  op.pid = get_pid();
  op.reply_stamp = bpf_ktime_get_boot_ns();
  //read recv_stamp
  ++varid;

}*/

SEC("uprobe")
int uprobe_ec_submit_transaction(struct pt_regs *ctx) {
  bpf_printk("Entered into uprobe_ec_submit_transaction\n");

  int varid = 150;
  struct op_k key;
  memset(&key, 0, sizeof(key));
  // read num
  struct VarField *vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (NULL != vf) {
    __u64 v = 0;
    v = fetch_register(ctx, vf->varloc.reg);
    __u64 num_addr = fetch_var_member_addr(v, vf);
    bpf_probe_read_user(&key.owner, sizeof(key.owner), (void *)num_addr);
  } else {
    bpf_printk("uprobe_submit_transaction got NULL vf at varid %d\n", varid);
  }
  // read tid
  ++varid;
  vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (NULL != vf) {
    __u64 v = 0;
    v = fetch_register(ctx, vf->varloc.reg);
    __u64 tid_addr = fetch_var_member_addr(v, vf);
    bpf_probe_read_user(&key.tid, sizeof(key.tid), (void *)tid_addr);
  } else {
    bpf_printk("uprobe_submit_transaction got NULL vf at varid %d\n", varid);
    return 0;
  }

  key.pid = get_pid();

  // TODO submit_transaction can get the objectid

  struct op_v *vp = bpf_map_lookup_elem(&ops, &key);
  if (NULL != vp) {
    //Ignore the EC ops currently
    bpf_map_delete_elem(&ops, &key);
  }
  return 0;
}
