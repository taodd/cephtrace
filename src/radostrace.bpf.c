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

void initialize_value(struct client_op_k key) {
  struct client_op_v val;
  memset(&val, 0, sizeof(val));
  bpf_map_update_elem(&ops, &key, &val, 0);
}

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

  initialize_value(key);
  struct client_op_v *val = bpf_map_lookup_elem(&ops, &key);
  if (val == NULL) {
    return 0;
  }
  memset(val, 0, sizeof(struct client_op_v));
  val->sent_stamp = bpf_ktime_get_boot_ns();
  val->tid = key.tid;
  val->cid = key.cid;
  val->rw = 0;
  // read osd id
  ++varid;
  vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (NULL != vf) {
    __u64 v = 0;
    v = fetch_register(ctx, vf->varloc.reg);
    __u64 osd_addr = fetch_var_member_addr(v, vf);
    bpf_probe_read_user(&val->target_osd, sizeof(val->target_osd), (void *)osd_addr);
    bpf_printk("uprobe_send_op got osd id %lld\n", val->target_osd);
  } else {
    bpf_printk("uprobe_send_op got NULL vf at varid %d\n", varid);
  }

  // read name length
  ++varid;
  vf = bpf_map_lookup_elem(&hprobes, &varid);
  int name_len = 0;
  if (NULL != vf) {
    __u64 v = 0;
    v = fetch_register(ctx, vf->varloc.reg);
    __u64 len_addr = fetch_var_member_addr(v, vf);
    bpf_probe_read_user(&name_len, sizeof(name_len), (void *)len_addr);
    bpf_printk("uprobe_send_op got name length %d\n", name_len);
  } else {
    bpf_printk("uprobe_send_op got NULL vf at varid %d\n", varid);
  }

  // read name
  ++varid;
  vf = bpf_map_lookup_elem(&hprobes, &varid);
  __u64 name_base = 0;
  if (NULL != vf) {
    __u64 v = 0;
    v = fetch_register(ctx, vf->varloc.reg);
    __u64 name_base_addr = fetch_var_member_addr(v, vf);
    bpf_probe_read_user(&name_base, sizeof(name_base), (void *)name_base_addr);
    bpf_printk("uprobe_send_op got name base addr %lld\n", name_base);
  } else {
    bpf_printk("uprobe_send_op got NULL vf at varid %d\n", varid);
  }

  name_len &= 127;
  bpf_probe_read_user(val->object_name, name_len, (void *)name_base);
  // read op flags
  ++varid;
  vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (NULL != vf) {
    __u64 v = 0;
    v = fetch_register(ctx, vf->varloc.reg);
    __u64 flags_addr = fetch_var_member_addr(v, vf);
    bpf_probe_read_user(&val->rw, sizeof(val->rw), (void *)flags_addr);
    bpf_printk("uprobe_send_op got flags %d\n", val->rw);
  } else {
    bpf_printk("uprobe_send_op got NULL vf at varid %d\n", varid);
  }

  // read m_pool
  ++varid;
  vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (NULL != vf) {
    __u64 v = 0;
    v = fetch_register(ctx, vf->varloc.reg);
    __u64 m_pool_addr = fetch_var_member_addr(v, vf);
    bpf_probe_read_user(&val->m_pool, sizeof(val->m_pool), (void *)m_pool_addr);
    bpf_printk("uprobe_send_op got m_pool %d\n", val->m_pool);
  } else {
    bpf_printk("uprobe_send_op got NULL vf at varid %d\n", varid);
  }
  
  // read m_seed
  ++varid;
  vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (NULL != vf) {
    __u64 v = 0;
    v = fetch_register(ctx, vf->varloc.reg);
    __u64 m_seed_addr = fetch_var_member_addr(v, vf);
    bpf_probe_read_user(&val->m_seed, sizeof(val->m_seed), (void *)m_seed_addr);
    bpf_printk("uprobe_send_op got m_seed %d\n", val->m_seed);
  } else {
    bpf_printk("uprobe_send_op got NULL vf at varid %d\n", varid);
  }
  
  // read acting _M_start
  ++varid;
  __u64 M_start;
  vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (NULL != vf) {
    __u64 v = 0;
    v = fetch_register(ctx, vf->varloc.reg);
    __u64 M_start_addr = fetch_var_member_addr(v, vf);
    bpf_probe_read_user(&M_start, sizeof(M_start), (void *)M_start_addr);
    bpf_printk("uprobe_send_op got M_start %d\n", M_start);
  } else {
    bpf_printk("uprobe_send_op got NULL vf at varid %d\n", varid);
    return 0;
  }

  // read acting _M_finish
  ++varid;
  __u64 m_finish;
  vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (NULL != vf) {
    __u64 v = 0;
    v = fetch_register(ctx, vf->varloc.reg);
    __u64 m_finish_addr = fetch_var_member_addr(v, vf);
    bpf_probe_read_user(&m_finish, sizeof(m_finish), (void *)m_finish_addr);
    bpf_printk("uprobe_send_op got m_finish %d\n", m_finish);
  } else {
    bpf_printk("uprobe_send_op got NULL vf at varid %d\n", varid);
    return 0;
  }

  for (int i = 0 ; i < 8; ++i) {
    val->acting[i] = -1;
    if (M_start < m_finish) {
	bpf_probe_read_user(&(val->acting[i]), sizeof(int), (void *)M_start);
	M_start += sizeof(int);
    } else {
	break;
    }
  }

  //read op->ops->m_holder->m_start
  ++varid;
  __u64 m_start;
  vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (NULL != vf) {
    __u64 v = 0;
    v = fetch_register(ctx, vf->varloc.reg);
    __u64 m_start_addr = fetch_var_member_addr(v, vf);
    bpf_probe_read_user(&m_start, sizeof(m_start), (void *)m_start_addr);
    bpf_printk("uprobe_send_op got m_start %lld\n", m_start);
  } else {
    bpf_printk("uprobe_send_op got NULL vf at varid %d\n", varid);
    return 0;
  }

  //read op->ops->m_holder->m_size
  ++varid;
  vf = bpf_map_lookup_elem(&hprobes, &varid);
  if (NULL != vf) {
    __u64 v = 0;
    v = fetch_register(ctx, vf->varloc.reg);
    __u64 m_size_addr = fetch_var_member_addr(v, vf);
    bpf_probe_read_user(&val->ops_size, sizeof(val->ops_size), (void *)m_size_addr);
    bpf_printk("uprobe_send_op got m_start %d\n", val->ops_size);
  } else {
    bpf_printk("uprobe_send_op got NULL vf at varid %d\n", varid);
    return 0;
  }

  val->ops_size &= 3;
  val->offset = 0;
  val->length = 0;
  bool has_extent_op = false;
  for (int i = 0; i  < 3; ++i) {
    if (i < val->ops_size) {
      bpf_probe_read_user(&(val->ops[i]), sizeof(val->ops[i]), (void *)m_start); 
      if (!has_extent_op && ceph_osd_op_extent(val->ops[i])){
        // read extent offset and length
        bpf_probe_read_user(&val->offset, sizeof(val->offset), (void *)(m_start + CEPH_OSD_OP_EXTENT_OFFSET_OFFSET)); 
        bpf_probe_read_user(&val->length, sizeof(val->length), (void *)(m_start + CEPH_OSD_OP_EXTENT_LENGTH_OFFSET)); 
	has_extent_op = true; // use first extent op's offset and length
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
	cls_len &= 7;
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

  //bpf_map_update_elem(&ops, &key, val, 0);// no need to update again here
  return 0;
}

SEC("uprobe")
int uprobe_finish_op(struct pt_regs *ctx) {
  bpf_printk("Entered uprobe_finish_op\n");
  int varid = 20;
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

