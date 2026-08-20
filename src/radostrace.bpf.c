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
} rb SEC(".maps"); // all submits use BPF_RB_NO_WAKEUP; userspace drains periodically

/* Global variables for struct offsets - set by userspace before loading */
const volatile __u32 CEPH_OSD_OP_SIZE = 0;
const volatile __u32 CEPH_OSD_OP_EXTENT_OFFSET_OFFSET = 0;
const volatile __u32 CEPH_OSD_OP_EXTENT_LENGTH_OFFSET = 0;
const volatile __u32 CEPH_OSD_OP_CLS_CLASS_OFFSET = 0;
const volatile __u32 CEPH_OSD_OP_CLS_METHOD_OFFSET = 0;
const volatile __u32 CEPH_OSD_OP_BUFFER_CARRIAGE_OFFSET = 0;
const volatile __u32 CEPH_OSD_OP_BUFFER_RAW_OFFSET = 0;
const volatile __u32 CEPH_OSD_OP_BUFFER_DATA_OFFSET = 0;

/* Every variable read at either probe is rooted at the Op* (or this->monc)
 * and its DWARF member chain is offset-only, so userspace collapses each
 * chain to a single precomputed offset at load time.  Each program fetches
 * its root registers once and does one bpf_probe_read_user per member -- no
 * per-var map lookup and no chain walking on the hot path.  Member offsets
 * are struct properties shared by both probes; only the registers holding
 * op/this differ per probe site. */
const volatile __u32 SEND_OP_REG = 0;
const volatile __u32 SEND_THIS_REG = 0;
const volatile __u32 FIN_OP_REG = 0;
const volatile __u32 FIN_THIS_REG = 0;
const volatile __s64 OFF_TID = 0;
const volatile __s64 OFF_MONC = 0;        /* this + OFF_MONC -> MonClient* */
const volatile __s64 OFF_GLOBAL_ID = 0;   /* monc + OFF_GLOBAL_ID */
const volatile __s64 OFF_TARGET_OSD = 0;
const volatile __s64 OFF_NAME_LEN = 0;
const volatile __s64 OFF_NAME_PTR = 0;
const volatile __s64 OFF_FLAGS = 0;
const volatile __s64 OFF_POOL = 0;
const volatile __s64 OFF_SEED = 0;
const volatile __s64 OFF_ACTING_START = 0;
const volatile __s64 OFF_ACTING_FINISH = 0;
const volatile __s64 OFF_OPS_START = 0;
const volatile __s64 OFF_OPS_SIZE = 0;

static struct client_op_v zero_val = {};

void initialize_value(struct client_op_k key) {
  bpf_map_update_elem(&ops, &key, &zero_val, 0);
}

#define READ_OP(dst, off) \
  bpf_probe_read_user(&(dst), sizeof(dst), (void *)(op + (off)))

static __always_inline __u64 read_cid(struct pt_regs *ctx, __u32 this_reg) {
  // this->monc->global_id: the one chain with an intermediate pointer
  __u64 self = fetch_register(ctx, this_reg);
  __u64 monc = 0;
  __u64 cid = 0;
  if (self != 0)
    bpf_probe_read_user(&monc, sizeof(monc), (void *)(self + OFF_MONC));
  if (monc != 0)
    bpf_probe_read_user(&cid, sizeof(cid), (void *)(monc + OFF_GLOBAL_ID));
  return cid;
}

SEC("uprobe")
int uprobe_send_op(struct pt_regs *ctx) {
  __u64 op = fetch_register(ctx, SEND_OP_REG);
  if (op == 0)
    return 0;

  struct client_op_k key;
  memset(&key, 0, sizeof(key));
  READ_OP(key.tid, OFF_TID);
  key.cid = read_cid(ctx, SEND_THIS_REG);

  initialize_value(key);
  struct client_op_v *val = bpf_map_lookup_elem(&ops, &key);
  if (val == NULL) {
    return 0;
  }
  val->tid = key.tid;
  val->cid = key.cid;

  READ_OP(val->target_osd, OFF_TARGET_OSD);
  READ_OP(val->rw, OFF_FLAGS);
  READ_OP(val->m_pool, OFF_POOL);
  READ_OP(val->m_seed, OFF_SEED);

  int name_len = 0;
  __u64 name_base = 0;
  READ_OP(name_len, OFF_NAME_LEN);
  READ_OP(name_base, OFF_NAME_PTR);
  name_len &= 127;
  bpf_probe_read_user(val->object_name, name_len, (void *)name_base);

  // acting vector bounds; zeros just fill the slots with -1 below
  __u64 M_start = 0;
  __u64 m_finish = 0;
  READ_OP(M_start, OFF_ACTING_START);
  READ_OP(m_finish, OFF_ACTING_FINISH);

  for (int i = 0 ; i < MAX_ACTING; ++i) {
    val->acting[i] = -1;
    if (M_start < m_finish) {
	bpf_probe_read_user(&(val->acting[i]), sizeof(int), (void *)M_start);
	M_start += sizeof(int);
    } else {
	break;
    }
  }

  // ops vector; a zero start pointer skips the decode loop
  __u64 m_start = 0;
  READ_OP(m_start, OFF_OPS_START);
  READ_OP(val->ops_size, OFF_OPS_SIZE);
  if (m_start == 0)
    val->ops_size = 0;

  // Keep ops_size as the true op count so userspace can report what was
  // dropped; only the capture loop is bounded by the array size.
  val->offset = 0;
  val->length = 0;
  for (__u32 i = 0; i  < MAX_CLIENT_OPS; ++i) {
    if (i < val->ops_size) {
      bpf_probe_read_user(&(val->ops[i]), sizeof(val->ops[i]), (void *)m_start); 
      if (ceph_osd_op_extent(val->ops[i])){
        // read extent offset and length
        bpf_probe_read_user(&val->offset, sizeof(val->offset), (void *)(m_start + CEPH_OSD_OP_EXTENT_OFFSET_OFFSET)); 
        bpf_probe_read_user(&val->length, sizeof(val->length), (void *)(m_start + CEPH_OSD_OP_EXTENT_LENGTH_OFFSET)); 
      } else if (ceph_osd_op_call(val->ops[i])) {
        // read class name and method name length
	__u8 cls_len = 0;
	__u8 method_len = 0;
	bpf_probe_read_user(&cls_len, sizeof(cls_len), (void *)m_start + CEPH_OSD_OP_CLS_CLASS_OFFSET);
	bpf_probe_read_user(&method_len, sizeof(method_len), (void *)m_start + CEPH_OSD_OP_CLS_METHOD_OFFSET);

	// read _carriage
	__u64 carriage = 0;
	bpf_probe_read_user(&carriage, sizeof(carriage), (void *)m_start + CEPH_OSD_OP_BUFFER_CARRIAGE_OFFSET);
	// read _carriage->_raw
	__u64 raw = 0;
	bpf_probe_read_user(&raw, sizeof(raw), (void *)carriage + CEPH_OSD_OP_BUFFER_RAW_OFFSET);
	// read _carriage->_raw->data
	__u64 data = 0;
	bpf_probe_read_user(&data, sizeof(data), (void *)raw + CEPH_OSD_OP_BUFFER_DATA_OFFSET);
        // read class name
	cls_len &= 15;
	bpf_probe_read_user(val->cls_ops[i].cls_name, cls_len, (void *)data);
	// read method name
	method_len &= 31;
	bpf_probe_read_user(val->cls_ops[i].method_name, method_len, (void *)data + cls_len);
      }
      m_start += CEPH_OSD_OP_SIZE;
    } else {
      break;
    }
  }

  val->sent_stamp = bpf_ktime_get_boot_ns();
  val->pid = get_pid();
  return 0;
}

SEC("uprobe")
int uprobe_finish_op(struct pt_regs *ctx) {
  __u64 op = fetch_register(ctx, FIN_OP_REG);
  if (op == 0)
    return 0;

  struct client_op_k key;
  memset(&key, 0, sizeof(key));
  READ_OP(key.tid, OFF_TID);
  key.cid = read_cid(ctx, FIN_THIS_REG);

  struct client_op_v *opv = bpf_map_lookup_elem(&ops, &key);

  if (NULL == opv) {
    bpf_printk("uprobe_finish_op, no previous send_op info, client id %lld, tid %lld\n", key.cid, key.tid);
    return 0;
  }
  opv->finish_stamp = bpf_ktime_get_boot_ns();
  // submit to ringbuf
  struct client_op_v *e = bpf_ringbuf_reserve(&rb, sizeof(struct client_op_v), 0);
  if (NULL == e) {
    bpf_map_delete_elem(&ops, &key);
    return 0;
  }
  *e = *opv;
  bpf_ringbuf_submit(e, BPF_RB_NO_WAKEUP);

  bpf_map_delete_elem(&ops, &key);
  
  return 0;
}

