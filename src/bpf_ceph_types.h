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

#define MAX_ACTING 16

#define CEPH_OSD_FLAG_READ 0x0010
#define CEPH_OSD_FLAG_WRITE 0x0020

/* Note: CEPH_OSD_OP_* struct offset constants are now defined as global variables
 * in radostrace.bpf.c and set by userspace via skel->rodata-> before BPF load.
 * This allows runtime configuration of struct offsets for different Ceph versions.
 */ 

static const __u8 flag_queued_for_pg=1 << 0;
static const __u8 flag_reached_pg =  1 << 1;
static const __u8 flag_delayed =     1 << 2;
static const __u8 flag_started =     1 << 3;
static const __u8 flag_sub_op_sent = 1 << 4;
static const __u8 flag_commit_sent = 1 << 5;

// Number of per-request ops radostrace captures. Requests carrying more than
// this (an RGW object PUT is typically 12) report the first MAX_CLIENT_OPS and
// the true total, so the userspace side can print "...+N".
#define MAX_CLIENT_OPS 3

typedef struct cls_op {
  char cls_name[16];
  char method_name[32];
} cls_op_t;

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
  char object_name[128];
  __u64 m_pool;
  __u32 m_seed;
  int acting[MAX_ACTING];
  __u64 offset;
  __u64 length;
  __u16 ops[MAX_CLIENT_OPS];
  __u32 ops_size;  // total ops in the request, may exceed MAX_CLIENT_OPS
  cls_op_t cls_ops[MAX_CLIENT_OPS];

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

// The `name` argument passed to BlueStore::log_latency{,_fn} is a short,
// human-readable label for the measured operation (a string literal like
// "kv_flush" or a __func__ such as "_txc_committed_kv"). It is the sole
// identifier we report: it is self-describing and version-stable, unlike
// the perfcounter index, whose value shifts between Ceph releases.
#define BS_LAT_NAME_LEN 40

struct bluestore_lat_v {
  __u32 pid;
  __u64 lat;
  char name[BS_LAT_NAME_LEN];
};

// Truncation length for object names captured from client ops and replica
// subops; covers RBD (rbd_data.<image>.<objno>) and most CephFS/RGW data
// objects. Longer names are cut at 63 chars.
#define OBJECT_NAME_LEN 64
#define MAX_DETAIL_OPS 8

// ceph::os::Transaction::Op is packed and has remained 72 bytes from Quincy
// through Tentacle. Its first member is the 32-bit ObjectStore opcode.
#define OBJECTSTORE_TXN_OP_SIZE 72
#define OSDTRACE_BUFFER_PTR_RAW_OFFSET 8
#define OSDTRACE_BUFFER_PTR_OFF_OFFSET 16
#define OSDTRACE_BUFFER_RAW_DATA_OFFSET 32

#define __CEPH_FORALL_OBJECTSTORE_TXN_OPS(f) \
  f(NOP, 0, "nop") \
  f(CREATE, 7, "create") \
  f(COLL_MOVE, 8, "coll_move") \
  f(TOUCH, 9, "touch") \
  f(WRITE, 10, "write") \
  f(ZERO, 11, "zero") \
  f(TRUNCATE, 12, "truncate") \
  f(REMOVE, 13, "remove") \
  f(SETATTR, 14, "setattr") \
  f(SETATTRS, 15, "setattrs") \
  f(RMATTR, 16, "rmattr") \
  f(CLONE, 17, "clone") \
  f(CLONERANGE, 18, "clonerange") \
  f(TRIMCACHE, 19, "trimcache") \
  f(MKCOLL, 20, "mkcoll") \
  f(RMCOLL, 21, "rmcoll") \
  f(COLL_ADD, 22, "coll_add") \
  f(COLL_REMOVE, 23, "coll_remove") \
  f(COLL_SETATTR, 24, "coll_setattr") \
  f(COLL_RMATTR, 25, "coll_rmattr") \
  f(COLL_SETATTRS, 26, "coll_setattrs") \
  f(RMATTRS, 28, "rmattrs") \
  f(COLL_RENAME, 29, "coll_rename") \
  f(CLONERANGE2, 30, "clonerange2") \
  f(OMAP_CLEAR, 31, "omap_clear") \
  f(OMAP_SETKEYS, 32, "omap_setkeys") \
  f(OMAP_RMKEYS, 33, "omap_rmkeys") \
  f(OMAP_SETHEADER, 34, "omap_setheader") \
  f(SPLIT_COLLECTION, 35, "split_collection") \
  f(SPLIT_COLLECTION2, 36, "split_collection2") \
  f(OMAP_RMKEYRANGE, 37, "omap_rmkeyrange") \
  f(COLL_MOVE_RENAME, 38, "coll_move_rename") \
  f(SETALLOCHINT, 39, "setallochint") \
  f(COLL_HINT, 40, "coll_hint") \
  f(TRY_RENAME, 41, "try_rename") \
  f(COLL_SET_BITS, 42, "coll_set_bits") \
  f(MERGE_COLLECTION, 43, "merge_collection") \
  f(TOUCH_TEMP, 44, "touch_temp")

enum objectstore_txn_opcode {
#define GENERATE_TXN_ENUM(op, value, name) OBJECTSTORE_TXN_OP_##op = value,
  __CEPH_FORALL_OBJECTSTORE_TXN_OPS(GENERATE_TXN_ENUM)
#undef GENERATE_TXN_ENUM
};

/* Allocator tracing (-A) */
#define ALLOC_NAME_LEN 32
#define ALLOC_MAX_EXTENTS 6
// nested allocate() calls per thread we track (HybridAllocator falls
// through to its internal BitmapAllocator, HybridBtree2Allocator calls
// its base class allocate)
#define ALLOC_MAX_DEPTH 4
// hprobes slot holding the {"this","asok_hook","name","_M_dataplus","_M_p"}
// varpath harvested from {AllocatorBase,Allocator}::get_name; every
// allocate() entry probe reuses it ("this" sits in the same register)
#define ALLOC_NAME_VARID 390

// key of an in-flight allocate() call; depth disambiguates nesting.
// Contains implicit padding, always memset before filling.
struct alloc_k {
  __u64 ptid;
  __u32 depth;
};

// stashed at allocate() entry, consumed by the shared uretprobe
struct alloc_inflight {
  char name[ALLOC_NAME_LEN];
  char comm[16];
  __u32 tid;
  __u32 start_off;   // offset of _M_start within PExtentVector
  __u32 finish_off;  // offset of _M_finish within PExtentVector
  __u64 want;
  __u64 unit;
  __u64 max_alloc;
  __s64 hint;
  __u64 extents;     // PExtentVector *
  __u64 ts;
};

struct alloc_ext {
  __u64 offset;
  __u64 length;
};

// ringbuf event; sizeof() must stay distinct from op_v, bluestore_lat_v
// (handle_event dispatches ringbuf events by size)
struct alloc_v {
  __u32 pid;
  __u32 tid;
  char comm[16];
  char name[ALLOC_NAME_LEN];
  __u32 depth;       // >0 = nested (e.g. hybrid fell back to its bitmap)
  __u32 nextents;    // total extents returned (may exceed the array below)
  __u64 want;
  __u64 unit;
  __u64 max_alloc;
  __s64 hint;
  __s64 rval;        // bytes allocated, or -errno
  __u64 lat;         // ns
  struct alloc_ext ext[ALLOC_MAX_EXTENTS];
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
  char object_name[OBJECT_NAME_LEN];
  __u32 detail_ops[MAX_DETAIL_OPS];
  cls_op_t cls_ops[MAX_DETAIL_OPS];
  __u32 detail_ops_captured;
  __u32 detail_ops_total;
  __u32 detail_ops_unavailable;
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
  struct Field fields[10];
  int size;
};
#else
struct VarField {
  VarLocation varloc;
  std::vector<Field> fields;
};

struct VarField_Kernel {
  VarLocation varloc;
  struct Field fields[10];
  int size;
};
#endif


/*
 * osd ops
 *
 * WARNING: do not use these op codes directly.  Use the helpers
 * defined below instead.  In certain cases, op code behavior was
 * redefined, resulting in special-cases in the helpers.
 */
#define CEPH_OSD_OP_MODE       0xf000
#define CEPH_OSD_OP_MODE_RD    0x1000
#define CEPH_OSD_OP_MODE_WR    0x2000
#define CEPH_OSD_OP_MODE_RMW   0x3000
#define CEPH_OSD_OP_MODE_SUB   0x4000
#define CEPH_OSD_OP_MODE_CACHE 0x8000

#define CEPH_OSD_OP_TYPE       0x0f00
#define CEPH_OSD_OP_TYPE_DATA  0x0200
#define CEPH_OSD_OP_TYPE_ATTR  0x0300
#define CEPH_OSD_OP_TYPE_EXEC  0x0400
#define CEPH_OSD_OP_TYPE_PG    0x0500
//      LEAVE UNUSED           0x0600 used to be multiobject ops

#define __CEPH_OSD_OP1(mode, nr) \
	(CEPH_OSD_OP_MODE_##mode | (nr))

#define __CEPH_OSD_OP(mode, type, nr) \
	(CEPH_OSD_OP_MODE_##mode | CEPH_OSD_OP_TYPE_##type | (nr))

#define __CEPH_FORALL_OSD_OPS(f)					    \
	/** data **/							    \
	/* read */							    \
	f(READ,		__CEPH_OSD_OP(RD, DATA, 1),	"read")		    \
	f(STAT,		__CEPH_OSD_OP(RD, DATA, 2),	"stat")		    \
	f(MAPEXT,	__CEPH_OSD_OP(RD, DATA, 3),	"mapext")	    \
	f(CHECKSUM,	__CEPH_OSD_OP(RD, DATA, 31),	"checksum")	    \
									    \
	/* fancy read */						    \
	f(MASKTRUNC,	__CEPH_OSD_OP(RD, DATA, 4),	"masktrunc")	    \
	f(SPARSE_READ,	__CEPH_OSD_OP(RD, DATA, 5),	"sparse-read")	    \
									    \
	f(NOTIFY,	__CEPH_OSD_OP(RD, DATA, 6),	"notify")	    \
	f(NOTIFY_ACK,	__CEPH_OSD_OP(RD, DATA, 7),	"notify-ack")	    \
									    \
	/* versioning */						    \
	f(ASSERT_VER,	__CEPH_OSD_OP(RD, DATA, 8),	"assert-version")   \
									    \
	f(LIST_WATCHERS, __CEPH_OSD_OP(RD, DATA, 9),	"list-watchers")    \
									    \
	f(LIST_SNAPS,	__CEPH_OSD_OP(RD, DATA, 10),	"list-snaps")	    \
									    \
	/* sync */							    \
	f(SYNC_READ,	__CEPH_OSD_OP(RD, DATA, 11),	"sync_read")	    \
									    \
	/* write */							    \
	f(WRITE,	__CEPH_OSD_OP(WR, DATA, 1),	"write")	    \
	f(WRITEFULL,	__CEPH_OSD_OP(WR, DATA, 2),	"writefull")	    \
	f(TRUNCATE,	__CEPH_OSD_OP(WR, DATA, 3),	"truncate")	    \
	f(ZERO,		__CEPH_OSD_OP(WR, DATA, 4),	"zero")		    \
	f(DELETE,	__CEPH_OSD_OP(WR, DATA, 5),	"delete")	    \
									    \
	/* fancy write */						    \
	f(APPEND,	__CEPH_OSD_OP(WR, DATA, 6),	"append")	    \
	f(STARTSYNC,	__CEPH_OSD_OP(WR, DATA, 7),	"startsync")	    \
	f(SETTRUNC,	__CEPH_OSD_OP(WR, DATA, 8),	"settrunc")	    \
	f(TRIMTRUNC,	__CEPH_OSD_OP(WR, DATA, 9),	"trimtrunc")	    \
									    \
	f(TMAPUP,	__CEPH_OSD_OP(RMW, DATA, 10),	"tmapup")	    \
	f(TMAPPUT,	__CEPH_OSD_OP(WR, DATA, 11),	"tmapput")	    \
	f(TMAPGET,	__CEPH_OSD_OP(RD, DATA, 12),	"tmapget")	    \
									    \
	f(CREATE,	__CEPH_OSD_OP(WR, DATA, 13),	"create")	    \
	f(ROLLBACK,	__CEPH_OSD_OP(WR, DATA, 14),	"rollback")	    \
									    \
	f(WATCH,	__CEPH_OSD_OP(WR, DATA, 15),	"watch")	    \
									    \
	/* omap */							    \
	f(OMAPGETKEYS,	__CEPH_OSD_OP(RD, DATA, 17),	"omap-get-keys")    \
	f(OMAPGETVALS,	__CEPH_OSD_OP(RD, DATA, 18),	"omap-get-vals")    \
	f(OMAPGETHEADER, __CEPH_OSD_OP(RD, DATA, 19),	"omap-get-header")  \
	f(OMAPGETVALSBYKEYS, __CEPH_OSD_OP(RD, DATA, 20), "omap-get-vals-by-keys") \
	f(OMAPSETVALS,	__CEPH_OSD_OP(WR, DATA, 21),	"omap-set-vals")    \
	f(OMAPSETHEADER, __CEPH_OSD_OP(WR, DATA, 22),	"omap-set-header")  \
	f(OMAPCLEAR,	__CEPH_OSD_OP(WR, DATA, 23),	"omap-clear")	    \
	f(OMAPRMKEYS,	__CEPH_OSD_OP(WR, DATA, 24),	"omap-rm-keys")	    \
	f(OMAPRMKEYRANGE, __CEPH_OSD_OP(WR, DATA, 44),	"omap-rm-key-range") \
	f(OMAP_CMP,	__CEPH_OSD_OP(RD, DATA, 25),	"omap-cmp")	    \
									    \
	/* tiering */							    \
	f(COPY_FROM,	__CEPH_OSD_OP(WR, DATA, 26),	"copy-from")	    \
	f(COPY_FROM2,	__CEPH_OSD_OP(WR, DATA, 45),	"copy-from2")	    \
	/* was copy-get-classic */					\
	f(UNDIRTY,	__CEPH_OSD_OP(WR, DATA, 28),	"undirty")	    \
	f(ISDIRTY,	__CEPH_OSD_OP(RD, DATA, 29),	"isdirty")	    \
	f(COPY_GET,	__CEPH_OSD_OP(RD, DATA, 30),	"copy-get")	    \
	f(CACHE_FLUSH,	__CEPH_OSD_OP(CACHE, DATA, 31),	"cache-flush")	    \
	f(CACHE_EVICT,	__CEPH_OSD_OP(CACHE, DATA, 32),	"cache-evict")	    \
	f(CACHE_TRY_FLUSH, __CEPH_OSD_OP(CACHE, DATA, 33), "cache-try-flush") \
									    \
	/* convert tmap to omap */					    \
	f(TMAP2OMAP,	__CEPH_OSD_OP(RMW, DATA, 34),	"tmap2omap")	    \
									    \
	/* hints */							    \
	f(SETALLOCHINT,	__CEPH_OSD_OP(WR, DATA, 35),	"set-alloc-hint")   \
                                                                            \
	/* cache pin/unpin */						    \
	f(CACHE_PIN,	__CEPH_OSD_OP(WR, DATA, 36),	"cache-pin")        \
	f(CACHE_UNPIN,	__CEPH_OSD_OP(WR, DATA, 37),	"cache-unpin")      \
									    \
	/* ESX/SCSI */							    \
	f(WRITESAME,	__CEPH_OSD_OP(WR, DATA, 38),	"write-same")	    \
	f(CMPEXT,	__CEPH_OSD_OP(RD, DATA, 32),	"cmpext")	    \
									    \
	/* Extensible */						    \
	f(SET_REDIRECT,	__CEPH_OSD_OP(WR, DATA, 39),	"set-redirect")	    \
	f(SET_CHUNK,	__CEPH_OSD_OP(CACHE, DATA, 40),	"set-chunk")	    \
	f(TIER_PROMOTE,	__CEPH_OSD_OP(WR, DATA, 41),	"tier-promote")	    \
	f(UNSET_MANIFEST, __CEPH_OSD_OP(WR, DATA, 42),	"unset-manifest")   \
	f(TIER_FLUSH, __CEPH_OSD_OP(CACHE, DATA, 43),	"tier-flush")	    \
	f(TIER_EVICT, __CEPH_OSD_OP(CACHE, DATA, 44),	"tier-evict")	    \
									    \
	/** attrs **/							    \
	/* read */							    \
	f(GETXATTR,	__CEPH_OSD_OP(RD, ATTR, 1),	"getxattr")	    \
	f(GETXATTRS,	__CEPH_OSD_OP(RD, ATTR, 2),	"getxattrs")	    \
	f(CMPXATTR,	__CEPH_OSD_OP(RD, ATTR, 3),	"cmpxattr")	    \
									    \
	/* write */							    \
	f(SETXATTR,	__CEPH_OSD_OP(WR, ATTR, 1),	"setxattr")	    \
	f(SETXATTRS,	__CEPH_OSD_OP(WR, ATTR, 2),	"setxattrs")	    \
	f(RESETXATTRS,	__CEPH_OSD_OP(WR, ATTR, 3),	"resetxattrs")	    \
	f(RMXATTR,	__CEPH_OSD_OP(WR, ATTR, 4),	"rmxattr")	    \
									    \
	/** subop **/							    \
	f(PULL,		__CEPH_OSD_OP1(SUB, 1),		"pull")		    \
	f(PUSH,		__CEPH_OSD_OP1(SUB, 2),		"push")		    \
	f(BALANCEREADS,	__CEPH_OSD_OP1(SUB, 3),		"balance-reads")    \
	f(UNBALANCEREADS, __CEPH_OSD_OP1(SUB, 4),	"unbalance-reads")  \
	f(SCRUB,	__CEPH_OSD_OP1(SUB, 5),		"scrub")	    \
	f(SCRUB_RESERVE, __CEPH_OSD_OP1(SUB, 6),	"scrub-reserve")    \
	f(SCRUB_UNRESERVE, __CEPH_OSD_OP1(SUB, 7),	"scrub-unreserve")  \
	/* 8 used to be scrub-stop */					\
	f(SCRUB_MAP,	__CEPH_OSD_OP1(SUB, 9),		"scrub-map")	    \
									    \
	/** exec **/							    \
	/* note: the RD bit here is wrong; see special-case below in helper */ \
	f(CALL,		__CEPH_OSD_OP(RD, EXEC, 1),	"call")		    \
									    \
	/** pg **/							    \
	f(PGLS,		__CEPH_OSD_OP(RD, PG, 1),	"pgls")		    \
	f(PGLS_FILTER,	__CEPH_OSD_OP(RD, PG, 2),	"pgls-filter")	    \
	f(PG_HITSET_LS,	__CEPH_OSD_OP(RD, PG, 3),	"pg-hitset-ls")	    \
	f(PG_HITSET_GET, __CEPH_OSD_OP(RD, PG, 4),	"pg-hitset-get")    \
	f(PGNLS,	__CEPH_OSD_OP(RD, PG, 5),	"pgnls")	    \
	f(PGNLS_FILTER,	__CEPH_OSD_OP(RD, PG, 6),	"pgnls-filter")     \
	f(SCRUBLS, __CEPH_OSD_OP(RD, PG, 7), "scrubls")

enum {
#define GENERATE_ENUM_ENTRY(op, opcode, str)	CEPH_OSD_OP_##op = (opcode),
__CEPH_FORALL_OSD_OPS(GENERATE_ENUM_ENTRY)
#undef GENERATE_ENUM_ENTRY
};

static inline int ceph_osd_op_call(int op)
{
  return op == CEPH_OSD_OP_CALL;
}

static inline int ceph_osd_op_extent(int op)
{
    return op == CEPH_OSD_OP_READ ||
	   op == CEPH_OSD_OP_SPARSE_READ ||
	   op == CEPH_OSD_OP_SYNC_READ ||
	   op == CEPH_OSD_OP_WRITE ||
	   op == CEPH_OSD_OP_WRITEFULL ||
	   op == CEPH_OSD_OP_ZERO ||
	   op == CEPH_OSD_OP_APPEND ||
	   op == CEPH_OSD_OP_MAPEXT ||
	   op == CEPH_OSD_OP_CMPEXT ||
	   op == CEPH_OSD_OP_OMAPSETVALS ||
	   op == CEPH_OSD_OP_OMAPGETKEYS;
}

static inline int ceph_osd_op_type_data(int op)
{
	return (op & CEPH_OSD_OP_TYPE) == CEPH_OSD_OP_TYPE_DATA;
}
static inline int ceph_osd_op_type_attr(int op)
{
	return (op & CEPH_OSD_OP_TYPE) == CEPH_OSD_OP_TYPE_ATTR;
}
static inline int ceph_osd_op_type_exec(int op)
{
	return (op & CEPH_OSD_OP_TYPE) == CEPH_OSD_OP_TYPE_EXEC;
}
static inline int ceph_osd_op_type_pg(int op)
{
	return (op & CEPH_OSD_OP_TYPE) == CEPH_OSD_OP_TYPE_PG;
}


/*const char * ceph_osd_op_str(int opc) {
    const char *op_str = NULL;
#define GENERATE_CASE_ENTRY(op, opcode, str)	case CEPH_OSD_OP_##op: op_str=str; break;
    switch (opc) {
    __CEPH_FORALL_OSD_OPS(GENERATE_CASE_ENTRY)
    }
    return op_str;
}*/

#endif
