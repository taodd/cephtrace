#define BPF_KERNEL_SPACE

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <stdbool.h>
#include <string.h>

#include "bpf_ceph_types.h"
#include "bpf_utils.h"
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

// struct op_v no longer fits on the BPF stack after adding object_name.
static struct op_v zero_op_v = {};

static __always_inline int read_hprobe_varfield(struct pt_regs *ctx, int varid, void *dst, size_t size) {
  struct VarField *vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (NULL != vf) {
    __u64 v = fetch_register(ctx, vf->varloc.reg);
    __u64 addr = fetch_var_member_addr(v, vf);
    bpf_probe_read_user(dst, size, (void *)addr);
    return 0;
  }
  bpf_printk("got NULL vf at varid %d\n", varid);
  return -1;
}

static __always_inline int read_hprobe_utime(struct pt_regs *ctx, int varid, __u64 *nsec_dst) {
  struct VarField *vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (NULL != vf) {
    __u64 v = fetch_register(ctx, vf->varloc.reg);
    __u64 addr = fetch_var_member_addr(v, vf);
    struct utime_t stamp;
    bpf_probe_read_user(&stamp.sec, sizeof(stamp.sec), (void *)addr);
    bpf_probe_read_user(&stamp.nsec, sizeof(stamp.nsec), (void *)(addr + 4));
    *nsec_dst = to_nsec(&stamp);
    return 0;
  }
  bpf_printk("got NULL vf at varid %d\n", varid);
  return -1;
}

SEC("uprobe")
int uprobe_enqueue_op(struct pt_regs *ctx) {
  int varid = 0;
  struct op_k key;
  memset(&key, 0, sizeof(key));

  __u16 op_type = 0;
  read_hprobe_varfield(ctx, varid++, &op_type, sizeof(op_type));
  if (op_type != MSG_OSD_OP && op_type != MSG_OSD_REPOP) {
    bpf_printk("uprobe_enqueue_op got a non osdop/osdrepop %d, ignore\n", op_type);
    return 0;
  }

  if (read_hprobe_varfield(ctx, varid++, &key.owner, sizeof(key.owner)) != 0)
    return 0;

  if (read_hprobe_varfield(ctx, varid++, &key.tid, sizeof(key.tid)) != 0)
    return 0;

  key.pid = get_pid();

  /* Retry detection.
   *
   * If an entry for (pid, owner, tid) is already in the map, an earlier
   * op with the same key is still in flight (its completion uprobe has
   * not fired yet) -- this is a client-side retry of an op the OSD is
   * still processing.  Without this guard, the bpf_map_update_elem call
   * below would overwrite the original's tracking with a freshly-memset
   * record; when the original later completes, log_op_stats picks up
   * the retry's record (deq == 0, every per-stage latency == 0, peer
   * slots reset to -1) and emits nonsense -- queue_lat in particular
   * underflows to ~UINT64_MAX because deq is zero while enq is the
   * retry's bpf_ktime_get_boot_ns().
   *
   * Ceph handles retries via PrimaryLogPG::already_complete() inside
   * do_op, so skipping the BPF update has no effect on what Ceph
   * reports to the client -- it only preserves our tracking of the
   * original op so its log_op_stats emission is well-formed.
   *
   * An age threshold separates a true retry (in-flight original) from
   * an orphan (entry left behind because some completion uprobe was
   * missed for an earlier op).  5 s is much longer than any healthy op
   * takes but well below the time it would take a tid to be legitimately
   * reused via a client session reset.  Orphans older than that are
   * cleaned up by falling through to the overwrite.
   */
  struct op_v *existing = bpf_map_lookup_elem(&ops, &key);
  if (existing != NULL) {
    __u64 age_ns = bpf_ktime_get_boot_ns() - existing->enqueue_stamp;
    if (age_ns < 5000000000ULL) {
      bpf_printk("uprobe_enqueue_op: retry detected, preserving original tracking (client=%lld tid=%lld age_ns=%llu)\n",
                 key.owner, key.tid, age_ns);
      return 0;
    }
    bpf_printk("uprobe_enqueue_op: orphan cleanup, overwriting stale entry (client=%lld tid=%lld age_ns=%llu)\n",
               key.owner, key.tid, age_ns);
  }

  bpf_map_update_elem(&ops, &key, &zero_op_v, 0);
  struct op_v *value = bpf_map_lookup_elem(&ops, &key);
  if (value == NULL)
    return 0;

  value->enqueue_stamp = bpf_ktime_get_boot_ns();
  value->pid = key.pid;
  value->tid = key.tid;
  value->owner = key.owner;
  value->op_type = op_type;
  value->pi.peer1 = -1;
  value->pi.peer2 = -1;

  if (read_hprobe_utime(ctx, varid++, &value->recv_stamp) != 0 ||
      read_hprobe_utime(ctx, varid++, &value->throttle_stamp) != 0 ||
      read_hprobe_utime(ctx, varid++, &value->recv_complete_stamp) != 0 ||
      read_hprobe_utime(ctx, varid++, &value->dispatch_stamp) != 0) {
    bpf_map_delete_elem(&ops, &key);
  }
  return 0;
}

SEC("uprobe")
int uprobe_dequeue_op(struct pt_regs *ctx) {
  bpf_printk("Entered into uprobe_dequeue_op\n");

  struct op_k key;
  memset(&key, 0, sizeof(key));
  int varid = 10;

  __u16 op_type = 0;
  read_hprobe_varfield(ctx, varid++, &op_type, sizeof(op_type));
  if (op_type != MSG_OSD_OP && op_type != MSG_OSD_REPOP) {
    bpf_printk("uprobe_dequeue_op got non osdop or repop type %d, ignore\n", op_type);
    return 0;
  }

  read_hprobe_varfield(ctx, varid++, &key.owner, sizeof(key.owner));
  if (read_hprobe_varfield(ctx, varid++, &key.tid, sizeof(key.tid)) != 0)
    return 0;

  key.pid = get_pid();

  bpf_printk("Entered into uprobe_dequeue_op key owner %lld, tid %lld\n",
             key.owner, key.tid);

  struct op_v *vp = bpf_map_lookup_elem(&ops, &key);
  if (NULL == vp) {
    bpf_printk("uprobe_dequeue_op, no previous enqueue_op info, owner %lld, tid %lld\n", key.owner, key.tid);
    return 0;
  }

  if (vp->dequeue_stamp == 0)
    vp->dequeue_stamp = bpf_ktime_get_boot_ns();

  __u64 m_pool = 0;
  if (read_hprobe_varfield(ctx, varid++, &m_pool, sizeof(m_pool)) != 0)
    return 0;
  vp->m_pool = m_pool;

  __u32 m_seed = 0;
  if (read_hprobe_varfield(ctx, varid++, &m_seed, sizeof(m_seed)) != 0)
    return 0;
  vp->m_seed = m_seed;

  __u64 ptid = bpf_get_current_pid_tgid();
  bpf_map_update_elem(&ptid_opk, &ptid, &key, 0);

  return 0;
}

SEC("uprobe")
int uprobe_execute_ctx(struct pt_regs *ctx) {
  bpf_printk("Entered into uprobe_execute_ctx\n");

  int varid = 20;
  struct op_k key;
  memset(&key, 0, sizeof(key));
  read_hprobe_varfield(ctx, varid++, &key.owner, sizeof(key.owner));
  if (read_hprobe_varfield(ctx, varid++, &key.tid, sizeof(key.tid)) != 0)
    return 0;

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

  __u64 name_len = 0;
  if (read_hprobe_varfield(ctx, varid++, &name_len, sizeof(name_len)) != 0)
    return 0;

  __u64 str_addr = 0;
  if (read_hprobe_varfield(ctx, varid++, &str_addr, sizeof(str_addr)) != 0)
    return 0;
  if (str_addr == 0 || name_len == 0)
    return 0;

  __u32 len = name_len;
  if (len > OBJECT_NAME_LEN - 1)
    len = OBJECT_NAME_LEN - 1;
  bpf_probe_read_user(vp->object_name, len & (OBJECT_NAME_LEN - 1),
                      (void *)str_addr);

  return 0;
}

SEC("uprobe")
int uprobe_submit_transaction(struct pt_regs *ctx) {
  bpf_printk("Entered into uprobe_submit_transaction\n");

  int varid = 30;
  struct op_k key;
  memset(&key, 0, sizeof(key));
  read_hprobe_varfield(ctx, varid++, &key.owner, sizeof(key.owner));
  if (read_hprobe_varfield(ctx, varid++, &key.tid, sizeof(key.tid)) != 0)
    return 0;

  key.pid = get_pid();

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

SEC("uprobe")
int uprobe_queue_transactions(struct pt_regs *ctx) {
  (void)ctx;
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
    bpf_printk("uprobe_queue_transaction, no previous ptid matched %d\n", ptid);
  }
  return 0;
}

SEC("uprobe")
int uprobe_do_write(struct pt_regs *ctx) {
  (void)ctx;
  bpf_printk("Entered into uprobe_do_write\n");
  __u64 ptid = bpf_get_current_pid_tgid();
  struct op_k *key = bpf_map_lookup_elem(&ptid_opk, &ptid);
  if (NULL != key) {
    struct op_v *vp = bpf_map_lookup_elem(&ops, key);
    if (NULL != vp) {
      vp->do_write_stamp = bpf_ktime_get_boot_ns();
    } else {
      bpf_printk(
          "uprobe_do_write, no previous key matched owner %lld, tid %lld\n",
          key->owner, key->tid);
    }
  } else {
    bpf_printk("uprobe_do_write, no previous tid matched %d\n", ptid);
  }
  return 0;
}

SEC("uprobe")
int uprobe_wctx_finish(struct pt_regs *ctx) {
  bpf_printk("Entered into uprobe_wctx_finish\n");
  __u64 ptid = bpf_get_current_pid_tgid();
  struct op_k *key = bpf_map_lookup_elem(&ptid_opk, &ptid);
  if (NULL != key) {
    struct op_v *vp = bpf_map_lookup_elem(&ops, key);
    if (NULL != vp) {
      vp->wctx_finish_stamp = bpf_ktime_get_boot_ns();
      bpf_map_delete_elem(&ptid_opk, &ptid);
      int varid = 60;
      __u32 seqid = 0;
      if (read_hprobe_varfield(ctx, varid++, &seqid, sizeof(seqid)) != 0) return 0;
      __u64 start = 0;
      if (read_hprobe_varfield(ctx, varid++, &start, sizeof(start)) != 0) return 0;

      struct ctx_k ck;
      ck.seqid = seqid;
      ck.start_stamp = start; 
      ck.pid = get_pid(); 

      bpf_map_update_elem(&ctx_opk, &ck, key, 0);
    } else {
      bpf_printk(
          "uprobe_wctx_finish, no previous key matched owner %lld, tid %lld\n",
          key->owner, key->tid);
    }
  } else {
    bpf_printk("uprobe_wctx_finish, no previous tid matched %d\n", ptid);
  }
  return 0;
}

SEC("uprobe")
int uprobe_txc_state_proc(struct pt_regs *ctx) {
  bpf_printk("Entered into uprobe_txc_state_proc\n");
  int varid = 70;
  __u32 seqid = 0;
  if (read_hprobe_varfield(ctx, varid++, &seqid, sizeof(seqid)) != 0) return 0;

  __u64 start = 0;
  if (read_hprobe_varfield(ctx, varid++, &start, sizeof(start)) != 0) return 0;

  struct ctx_k ck;
  ck.seqid = seqid;
  ck.start_stamp = start; 
  ck.pid = get_pid(); 
  struct op_k *key = bpf_map_lookup_elem(&ctx_opk, &ck);
  if (NULL == key) {
    bpf_printk("uprobe_txc_state_proc got NULL key at ck %lld %lld %lld\n", ck.seqid, ck.start_stamp, ck.pid);
    return 0;
  }
  __u32 state = 0;
  if (read_hprobe_varfield(ctx, varid++, &state, sizeof(state)) != 0) return 0;

  struct op_v *vp = bpf_map_lookup_elem(&ops, key);
  if (NULL == vp) return 0;

  struct VarField *vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (NULL == vf) return 0;
  __u64 v = fetch_register(ctx, vf->varloc.reg);

  if (state == 0) {  // STATE_PREPARE
    vp->aio_submit_stamp = bpf_ktime_get_boot_ns();
    __u64 pending_addr = fetch_var_member_addr(v, vf);
    int pending_num = 0;
    bpf_probe_read_user(&pending_num, sizeof(pending_num), (void *)pending_addr);
    vp->aio_size = pending_num;
    if (pending_num == 0)
      vp->aio_done_stamp = vp->aio_submit_stamp;
    bpf_printk("uprobe_txc_state_proc owner %lld tid %lld aio_submit_stamp = %lld", key->owner, key->tid, vp->aio_submit_stamp);
  } else if (state == 1) {  // STATE_AIO_WAIT
    vp->aio_done_stamp = bpf_ktime_get_boot_ns();
    bpf_printk("uprobe_txc_state_proc owner %lld tid %lld aio_done_stamp = %lld", key->owner, key->tid, vp->aio_done_stamp);
  } else if (state == 2) {  // STATE_IO_DONE sending to kv queue
    vp->kv_submit_stamp = bpf_ktime_get_boot_ns();
    bpf_printk("uprobe_txc_state_proc owner %lld tid %lld kv_submit_stamp = %lld", key->owner, key->tid, vp->kv_submit_stamp);
  } else if (state == 4) {  // STATE_KV_SUBMITTED
    vp->kv_committed_stamp = bpf_ktime_get_boot_ns();
    bpf_printk("uprobe_txc_state_proc owner %lld tid %lld kv_committed_stamp = %lld", key->owner, key->tid, vp->kv_committed_stamp);
    bpf_map_delete_elem(&ctx_opk, &ck);
  }

  return 0;
}

SEC("uprobe")
int uprobe_log_op_stats(struct pt_regs *ctx) {
  bpf_printk("Entered into uprobe_log_op_stats\n");
  int varid = 90;
  struct op_k key;
  memset(&key, 0, sizeof(key));
  read_hprobe_varfield(ctx, varid++, &key.owner, sizeof(key.owner));
  if (read_hprobe_varfield(ctx, varid++, &key.tid, sizeof(key.tid)) != 0)
    return 0;

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

  bpf_map_delete_elem(&ops, &key);
  return 0;
}

SEC("uprobe")
int uprobe_log_op_stats_v2(struct pt_regs *ctx) {
  bpf_printk("Entered into uprobe_log_op_stats v2\n");
  int varid = 90;
  struct op_v *op = bpf_ringbuf_reserve(&rb, sizeof(struct op_v), 0);
  if (op == NULL)
    return 0;
  *op = zero_op_v;

  read_hprobe_varfield(ctx, varid++, &op->owner, sizeof(op->owner));
  if (read_hprobe_varfield(ctx, varid++, &op->tid, sizeof(op->tid)) != 0) {
    bpf_ringbuf_discard(op, 0);
    return 0;
  }

  op->pid = get_pid();
  op->reply_stamp = bpf_ktime_get_boot_ns();
  ++varid;
  op->wb = PT_REGS_PARM3(ctx);
  ++varid;
  op->rb = PT_REGS_PARM4(ctx);

  if (read_hprobe_utime(ctx, varid++, &op->recv_stamp) != 0) {
    bpf_ringbuf_discard(op, 0);
    return 0;
  }

  if (read_hprobe_varfield(ctx, varid++, &op->op_type, sizeof(op->op_type)) != 0) {
    bpf_ringbuf_discard(op, 0);
    return 0;
  }

  bpf_printk(" log_op_stats_v2 client %lld tid %lld recv_stamp %lld ", op->owner, op->tid, op->recv_stamp);
  bpf_printk(" inb %lld outb %lld op type %lld\n",op->wb, op->rb, op->op_type);
  bpf_ringbuf_submit(op, 0);
  return 0;
}

SEC("uprobe")
int uprobe_generate_subop(struct pt_regs *ctx)
{
  bpf_printk("Entered into uprobe_generate_subop\n");
  int varid = 100;
  struct op_k key;
  memset(&key, 0, sizeof(key));
  read_hprobe_varfield(ctx, varid++, &key.owner, sizeof(key.owner));
  if (read_hprobe_varfield(ctx, varid++, &key.tid, sizeof(key.tid)) != 0)
    return 0;

  key.pid = get_pid();

  struct op_v *vp = bpf_map_lookup_elem(&ops, &key);
  if (vp == NULL) {
    bpf_printk("uprobe_generate_subop got NULL vp for client %lld, tid %lld\n", key.owner, key.tid);
    return 0;
  }

  int peer_id = 0;
  if (read_hprobe_varfield(ctx, varid++, &peer_id, sizeof(peer_id)) == 0) {
    if (vp->pi.peer1 == -1) {
      vp->pi.peer1 = peer_id;
    } else {
      vp->pi.peer2 = peer_id;
    }
  } else {
    return 0;
  }
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
  read_hprobe_varfield(ctx, varid++, &key.owner, sizeof(key.owner));
  if (read_hprobe_varfield(ctx, varid++, &key.tid, sizeof(key.tid)) != 0)
    return 0;

  key.pid = get_pid();

  int osdid = -1;
  if (read_hprobe_varfield(ctx, varid++, &osdid, sizeof(osdid)) != 0)
    return 0;

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
  __u8 flag = PT_REGS_PARM2(ctx);
  bpf_printk("flag is %d\n", flag);
  if(!(flag & flag_delayed))
    return 0;
  struct op_k key;
  memset(&key, 0, sizeof(key));
  ++varid;
  read_hprobe_varfield(ctx, varid++, &key.owner, sizeof(key.owner));
  if (read_hprobe_varfield(ctx, varid++, &key.tid, sizeof(key.tid)) != 0)
    return 0;

  key.pid = get_pid();

  struct op_v *vp = bpf_map_lookup_elem(&ops, &key);
  if (vp == NULL) 
    return 0;

  __u32 len = 0;
  if (read_hprobe_varfield(ctx, varid++, &len, sizeof(len)) != 0)
    return 0;
  
  __u32 idx = vp->di.cnt;

  __u64 str_addr = 0;
  if (read_hprobe_varfield(ctx, varid++, &str_addr, sizeof(str_addr)) != 0)
    return 0;

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
  memset(&bsl, 0, sizeof(bsl));

  bpf_probe_read_user_str(bsl.name, sizeof(bsl.name), (void *)PT_REGS_PARM2(ctx));

  ++varid;
  if (read_hprobe_varfield(ctx, varid, &bsl.lat, sizeof(bsl.lat)) != 0)
    return 0;

  bsl.pid = get_pid();

  struct bluestore_lat_v *e = bpf_ringbuf_reserve(&rb, sizeof(struct bluestore_lat_v), 0);
  if (NULL == e) {
    return 0;
  }
  *e = bsl;
  bpf_ringbuf_submit(e, 0);

  return 0;
}

SEC("uprobe")
int uprobe_log_subop_stats(struct pt_regs *ctx)
{
  bpf_printk("Entered into log_subop_stats\n");
  int varid = 140;
  struct op_k key;
  memset(&key, 0, sizeof(key));
  read_hprobe_varfield(ctx, varid++, &key.owner, sizeof(key.owner));
  if (read_hprobe_varfield(ctx, varid++, &key.tid, sizeof(key.tid)) != 0)
    return 0;

  key.pid = get_pid();

  struct op_v *vp = bpf_map_lookup_elem(&ops, &key);
  if (NULL == vp) return 0; 

  __u64 len = 0;
  if (read_hprobe_varfield(ctx, varid++, &len, sizeof(len)) != 0)
    return 0;

  vp->wb = len;
  vp->reply_stamp = bpf_ktime_get_boot_ns();

  struct op_v *e = bpf_ringbuf_reserve(&rb, sizeof(struct op_v), 0);
  if (NULL == e) {
    return 0;
  }
  *e = *vp;
  bpf_ringbuf_submit(e, 0);

  bpf_map_delete_elem(&ops, &key);
  return 0;
}

SEC("uprobe")
int uprobe_ec_submit_transaction(struct pt_regs *ctx) {
  bpf_printk("Entered into uprobe_ec_submit_transaction\n");

  int varid = 150;
  struct op_k key;
  memset(&key, 0, sizeof(key));
  read_hprobe_varfield(ctx, varid++, &key.owner, sizeof(key.owner));
  if (read_hprobe_varfield(ctx, varid++, &key.tid, sizeof(key.tid)) != 0)
    return 0;

  key.pid = get_pid();

  struct op_v *vp = bpf_map_lookup_elem(&ops, &key);
  if (NULL != vp) {
    bpf_map_delete_elem(&ops, &key);
  }
  return 0;
}

SEC("uprobe")
int uprobe_txc_calc_cost(struct pt_regs *ctx)
{
  bpf_printk("Entered into _tcx_calc_cost\n");
  __u64 ptid = bpf_get_current_pid_tgid();
  struct op_k *key = bpf_map_lookup_elem(&ptid_opk, &ptid);
  if (NULL != key) {
    struct op_v *vp = bpf_map_lookup_elem(&ops, key);
    if (NULL != vp) {
      bpf_map_delete_elem(&ptid_opk, &ptid);
      int varid = 160;
      __u32 seqid = 0;
      if (read_hprobe_varfield(ctx, varid++, &seqid, sizeof(seqid)) != 0) return 0;
      __u64 start = 0;
      if (read_hprobe_varfield(ctx, varid++, &start, sizeof(start)) != 0) return 0;

      struct ctx_k ck;
      ck.seqid = seqid;
      ck.start_stamp = start; 
      ck.pid = get_pid(); 

      bpf_map_update_elem(&ctx_opk, &ck, key, 0);
    } else {
      bpf_printk(
          "txc_calc_cost, no previous key matched owner %lld, tid %lld\n",
          key->owner, key->tid);
    }
  } else {
    bpf_printk("txc_calc_cost, no previous tid matched %d\n", ptid);
  }

  return 0;
}

SEC("uprobe")
int uprobe_repop_commit(struct pt_regs *ctx)
{
  bpf_printk("Entered into repop_commit\n");
  int varid = 170;
  struct op_k key;
  memset(&key, 0, sizeof(key));
  read_hprobe_varfield(ctx, varid++, &key.owner, sizeof(key.owner));
  if (read_hprobe_varfield(ctx, varid++, &key.tid, sizeof(key.tid)) != 0)
    return 0;

  key.pid = get_pid();

  struct op_v *vp = bpf_map_lookup_elem(&ops, &key);
  if (NULL == vp) { 
    bpf_printk("repop_commit got NULL val at key client %lld tid %lld\n", key.owner, key.tid);
    return 0; 
  }

  __u64 len = 0;
  if (read_hprobe_varfield(ctx, varid++, &len, sizeof(len)) != 0)
    return 0;

  vp->wb = len;
  vp->reply_stamp = bpf_ktime_get_boot_ns();

  // MOSDRepOp::poid is populated by finish_decode() in do_repop(), before
  // repop_commit runs.  The userspace resolver lowers the Message* downcast
  // in these varpaths to ordinary offsets and pointer dereferences.
  __u64 name_len = 0;
  if (read_hprobe_varfield(ctx, varid++, &name_len, sizeof(name_len)) == 0 &&
      name_len > 0) {
    __u64 str_addr = 0;
    if (read_hprobe_varfield(ctx, varid++, &str_addr, sizeof(str_addr)) == 0 &&
        str_addr != 0) {
      __u32 name_read_len = name_len;
      if (name_read_len > OBJECT_NAME_LEN - 1)
        name_read_len = OBJECT_NAME_LEN - 1;
      bpf_probe_read_user(vp->object_name,
                          name_read_len & (OBJECT_NAME_LEN - 1),
                          (void *)str_addr);
    }
  }

  struct op_v *e = bpf_ringbuf_reserve(&rb, sizeof(struct op_v), 0);
  if (NULL == e) {
    return 0;
  }
  *e = *vp;
  bpf_ringbuf_submit(e, 0);

  bpf_map_delete_elem(&ops, &key);
  return 0;
}

SEC("uprobe")
int uprobe_mark_flag_point(struct pt_regs *ctx)
{
  bpf_printk("Entered into mark_flag_point\n");
  int varid = 180;
  __u8 flag = PT_REGS_PARM2(ctx);
  bpf_printk("flag is %d\n", flag);
  if(!(flag & flag_delayed))
    return 0;

  struct op_k key;
  memset(&key, 0, sizeof(key));
  ++varid;
  read_hprobe_varfield(ctx, varid++, &key.owner, sizeof(key.owner));
  if (read_hprobe_varfield(ctx, varid++, &key.tid, sizeof(key.tid)) != 0)
    return 0;

  key.pid = get_pid();

  struct op_v *vp = bpf_map_lookup_elem(&ops, &key);
  if (vp == NULL)
    return 0;

  __u64 str_addr = PT_REGS_PARM3(ctx);

  __u32 idx = vp->di.cnt;
  if (idx >= 5)
    return 0;

  bpf_probe_read_user_str(vp->di.delays[idx], 32, (void *)str_addr);
  vp->di.cnt++;
  return 0;
}

SEC("uprobe")
int uprobe_log_latency_fn(struct pt_regs *ctx)
{
  bpf_printk("Entered into log_latency_fn\n");
  int varid = 190;
  struct bluestore_lat_v bsl;
  memset(&bsl, 0, sizeof(bsl));

  bpf_probe_read_user_str(bsl.name, sizeof(bsl.name), (void *)PT_REGS_PARM2(ctx));

  ++varid;
  if (read_hprobe_varfield(ctx, varid, &bsl.lat, sizeof(bsl.lat)) != 0)
    return 0;

  bsl.pid = get_pid();

  struct bluestore_lat_v *e = bpf_ringbuf_reserve(&rb, sizeof(struct bluestore_lat_v), 0);
  if (NULL == e) {
    return 0;
  }
  *e = bsl;
  bpf_ringbuf_submit(e, 0);

  return 0;
}
