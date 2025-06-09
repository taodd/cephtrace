#ifndef BPF_UTILS_H
#define BPF_UTILS_H

#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

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
  deference modified ctx error 
  switch (reg) { 
        case 6: v = ctx->rbp; break; 
        case 7: v = ctx->rsp; break; 
        case 0: v = ctx->rax; break; 
        case 1: v = PT_REGS_PARM3(ctx); //rdx break; 
        case 2: v = PT_REGS_PARM4(ctx); //rcx break;
        case 3: v = ctx->rbx; break;
        case 4: v = PT_REGS_PARM2(ctx); //rsi break;
        case 5: v = PT_REGS_PARM1(ctx); //rdi break;
        case 8: v = PT_REGS_PARM5(ctx); //r8 break;
        case 9: v = PT_REGS_PARM6(ctx); //r9 break;
        default: break;
  }
  */ 
  return v;
}


// deal with member dereference vf->size > 1
__u64 fetch_var_member_addr(__u64 cur_addr, struct VarField *vf) {
  if (vf == NULL) return 0;
  if (cur_addr == 0) return 0;
  //Special handling for the first member
  __u64 tmpaddr;
  if (vf->varloc.stack) {
    cur_addr += vf->varloc.offset;
    if (vf->fields[1].pointer) {
      bpf_probe_read_user(&tmpaddr, sizeof(tmpaddr), (void *)cur_addr);
      cur_addr = tmpaddr;
    }
  }
  cur_addr += vf->fields[1].offset;
  int bound = MIN(MAX(vf->size, 0), 9);
  for (int i = 2; i < bound; i++) { // Bounded loop supported since v5.3 kernel
    if (vf->fields[i].pointer) {
      bpf_probe_read_user(&tmpaddr, sizeof(tmpaddr), (void *)cur_addr);
      cur_addr = tmpaddr;
    } 
    cur_addr += vf->fields[i].offset;
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

#endif
