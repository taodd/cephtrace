#include <errno.h>
#include <stdio.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <time.h>
#include <getopt.h>
#include "uprobe_osd.skel.h"
#include <vector>
#include <map>
#include <unordered_map>
#include <string>
#include <iostream>
#include <cassert>
#include <cstring>
#include <ctime>
extern "C" {
#include <unistd.h>
#include <fcntl.h>
#include <elfutils/libdwfl.h>
#include <elfutils/libdw.h>
#include <dwarf.h>
#include <elf.h>
}

#define MAX_CNT 100000ll
#define MAX_OSD 4000
#define PATH_MAX 4096

#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

Dwfl_Module *mod = NULL;
Dwarf_Die *cur_cu = NULL;
Dwarf_CFI * cfi_debug = NULL;
Dwarf_CFI * cfi_eh = NULL;
Dwarf_Addr cfi_debug_bias;
Dwarf_Addr cfi_eh_bias;


typedef struct VarLocation {
    int reg;
    int offset;
    bool stack;
    VarLocation(){reg=0; offset=0; stack=false;}
} VarLocation;

struct Field {
    int offset;
    bool pointer;
};

struct VarField {
    struct VarLocation varloc;
    std::vector<Field> fields;
};

struct VarField_Kernel {
    struct VarLocation varloc;
    struct Field fields[8];
    int size;
};

typedef std::map<std::string, std::vector<std::vector<std::string>> > probes_t;
typedef std::map<std::string, int> func_id_t;

func_id_t func_id = {
    {"OSD::enqueue_op", 0},
    {"OSD::dequeue_op", 10},
    {"PrimaryLogPG::execute_ctx", 20},
    {"ReplicatedBackend::submit_transaction", 30}, 
    {"BlueStore::queue_transactions", 40},
    {"BlueStore::_do_write", 50},
    {"BlueStore::_wctx_finish", 60},
    {"BlueStore::_txc_state_proc", 70},
    {"BlueStore::_txc_apply_kv", 80},
    {"PrimaryLogPG::log_op_stats", 90} 
};

std::vector<std::string> probe_units = {"OSD.cc", "BlueStore.cc", "PrimaryLogPG.cc", "ReplicatedBackend.cc"};

probes_t probes = {

    { "OSD::enqueue_op", { 
			     {"op", "px", "request", "header", "type"},
			     {"op", "px", "reqid", "name", "_num"}, 
			     {"op", "px", "reqid", "tid"},
			     {"op", "px", "request", "recv_stamp"},
			     {"op", "px", "request", "recv_complete_stamp"},
			     {"op", "px", "request", "dispatch_stamp"}
			 } 
    }, 
    
    {"OSD::dequeue_op", {
			    {"op", "px", "request", "header", "type"},
			    {"op", "px", "reqid", "name", "_num"}, 
			    {"op", "px", "reqid", "tid"}
			}
    },

    { "PrimaryLogPG::execute_ctx", { 
				       {"ctx", "reqid", "name", "_num"}, 
				       {"ctx", "reqid", "tid"}  
				   } 
    },

    { "ReplicatedBackend::submit_transaction", { 
						   {"reqid", "name", "_num"}, 
						   {"reqid", "tid"} 
					       } 
    }, 

    {
	"BlueStore::queue_transactions", {}
    },

    { "BlueStore::_do_write", {
			       //{"txc"},
			       //{"offset"},
			       //{"length"}
   			      }
    },

    { "BlueStore::_wctx_finish", {
				     //{"txc"}
				 }
    },

    {
	"BlueStore::_txc_state_proc", {
	                                {"txc", "state"}
	                              }
    },
    
    {
	"BlueStore::_txc_apply_kv", {
	                                {"txc", "state"}
	                            }
    },


    { "PrimaryLogPG::log_op_stats", { 
					{"op", "reqid", "name", "_num"}, 
					{"op", "reqid", "tid"}, 
					{"inb"}, 
					{"outb"} 
				    } 
    }
    
};

std::map<std::string, std::vector<VarField>> func2vf;
std::map<std::string, Dwarf_Addr> func2pc;

static void translate_expr(Dwarf_Attribute *fb_attr, Dwarf_Op *expr, Dwarf_Addr pc, VarLocation &varloc);
static Dwfl* create_dwfl (int fd, const char *fname);

typedef std::unordered_map<std::string, Dwarf_Die> cu_type_cache_t;
typedef std::unordered_map<void*, cu_type_cache_t> mod_cu_type_cache_t;

mod_cu_type_cache_t global_type_cache;

Dwarf_Die * resolve_typedecl(Dwarf_Die *type);
static const char* cache_type_prefix(Dwarf_Die* type);


enum mode_e {
    MODE_AVG=1, MODE_MAX
};

enum mode_e mode = MODE_AVG;

static __u64 bootstamp = 0;

static __u64 cnt = 0;
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

#define DEBUG printf

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

struct op_stat_s {
   __u64 recv_lat;
   __u64 dispatch_lat;
   __u64 queue_lat;
   __u64 osd_lat;
   __u64 bluestore_alloc_lat;
   __u64 bluestore_data_lat;
   __u64 bluestore_kv_lat;
   __u64 bluestore_lat;
   __u64 op_lat;
   __u64 r_cnt;
   __u64 w_cnt;
   __u64 rbytes;
   __u64 wbytes;
   __u64 max_recv_lat;
   __u64 max_dispatch_lat;
   __u64 max_queue_lat;
   __u64 max_osd_lat;
   __u64 max_bluestore_lat;
   __u64 max_op_lat;
};
int num_osd = 0;
int osds[MAX_OSD] = {0};
int pids[MAX_OSD] = {0};
struct op_stat_s op_stat[MAX_OSD];

struct timespec lasttime;
__u32 period = 0; 


// dwarf functions

static bool
die_has_loclist(Dwarf_Die *begin_die)
{
  Dwarf_Die die;
  Dwarf_Attribute loc;

  if (dwarf_child(begin_die, &die) != 0)
    return false;

  do
    {
      switch (dwarf_tag(&die))
        {
        case DW_TAG_formal_parameter:
        case DW_TAG_variable:
          if (dwarf_attr_integrate(&die, DW_AT_location, &loc)
           && dwarf_whatform(&loc) == DW_FORM_sec_offset)
            return true;
          break;
        default:
          if (dwarf_haschildren (&die))
            if (die_has_loclist(&die))
              return true;
          break;
        }
    }
  while (dwarf_siblingof (&die, &die) == 0);

  return false;
}


bool has_loclist()
{
    assert(cur_cu);
    return die_has_loclist(cur_cu);
}

Dwarf_Die * resolve_typedecl(Dwarf_Die *type) {

    const char* name = dwarf_diename(type);
    if(!name)
	return NULL;

    std::string type_name = cache_type_prefix(type) + std::string(name);
  
    for (auto i = global_type_cache.begin(); i != global_type_cache.end(); ++i)
    {
      cu_type_cache_t v = (*i).second;
      if (v.find(type_name) != v.end())
        return & (v[type_name]);
    }

    return NULL;

}

static const char*
cache_type_prefix(Dwarf_Die* type)
{
  switch (dwarf_tag(type))
    {
    case DW_TAG_enumeration_type:
      return "enum ";
    case DW_TAG_structure_type:
    case DW_TAG_class_type:
      // treating struct/class as equals
      return "struct ";
    case DW_TAG_union_type:
      return "union ";
    }
  return "";
}

int iterate_types_in_cu(Dwarf_Die *cu_die)
{
  assert (cu_die);
  assert (dwarf_tag(cu_die) == DW_TAG_compile_unit
	  || dwarf_tag(cu_die) == DW_TAG_type_unit
	  || dwarf_tag(cu_die) == DW_TAG_partial_unit);

  if (dwarf_tag(cu_die) == DW_TAG_partial_unit)
    return DWARF_CB_OK;
  
 
  cu_type_cache_t &v = global_type_cache[cu_die->addr]; 
  //TODO inner types process
  //bool has_inner_types = dwarf_srclang(cu_die) == DW_LANG_C_plus_plus;

  int rc = DWARF_CB_OK;
  Dwarf_Die die;

  if (dwarf_child(cu_die, &die) != 0)
    return rc;
  

  do
    /* We're only currently looking for named types,
     * although other types of declarations exist */
    switch (dwarf_tag(&die))
      {
      case DW_TAG_base_type:
      case DW_TAG_enumeration_type:
      case DW_TAG_structure_type:
      case DW_TAG_class_type:
      case DW_TAG_typedef:
      case DW_TAG_union_type:
	  {
	      const char *name = dwarf_diename(&die);
	      if (!name || dwarf_hasattr(&die, DW_AT_declaration)
		      /*TODO || has_only_decl_members(die)*/)
		  continue;
	      std::string type_name = cache_type_prefix(&die) + std::string(name);
	      if (v.find(type_name) == v.end())
		      v[type_name] = die;

	  }

        break;

      case DW_TAG_namespace:
	break;
      case DW_TAG_imported_unit:
	break;
      }
   while (rc == DWARF_CB_OK && dwarf_siblingof(&die, &die) == 0);

  return rc;
}


void traverse_module(
	Dwfl_Module *mod,
        Dwarf *dw, 	
	int (*callback)(Dwarf_Die*),
	bool want_type)
{
    assert(dw && mod);

    Dwarf_Off off = 0;
    size_t cuhl;
    Dwarf_Off noff;
    
    while (dwarf_nextcu (dw, off, &noff, &cuhl, NULL, NULL, NULL) == 0)
    {
        Dwarf_Die die_mem;
        Dwarf_Die *die;
        die = dwarf_offdie (dw, off + cuhl, &die_mem);
        /* Skip partial units. */
        if (dwarf_tag (die) == DW_TAG_compile_unit)
           (*callback)(die); 
        off = noff;
    }

     if (want_type)
     {
      // Process type units.
      Dwarf_Off off = 0;
      size_t cuhl;
      Dwarf_Off noff;
      uint64_t type_signature;
      while (dwarf_next_unit (dw, off, &noff, &cuhl, NULL, NULL, NULL, NULL,
			      &type_signature, NULL) == 0)
	{
          Dwarf_Die die_mem;
          Dwarf_Die *die;
          die = dwarf_offdie_types (dw, off + cuhl, &die_mem);
          if (dwarf_tag (die) == DW_TAG_type_unit)
            (*callback)(die);
          off = noff;
	}
     }
}

void print_die(Dwarf_Die *die) {
    //printf("DIE information:\n");
    //printf("  Offset: %llu\n", static_cast<unsigned long long>(dwarf_dieoffset(die)));
    //printf("  Tag: %s\n", dwarf_tag_string(dwarf_tag(die)));
    //printf("  Name: %s\n", dwarf_diename(die));

    /*TODO print attribute
    Dwarf_Attribute attr;
    Dwarf_Attribute *attr_result = nullptr;
    while ((attr_result = dwarf_attr_integrate(die, attr_result ? attr.code + 1 : 0, &attr)) != nullptr) {
        const char *attr_name = dwarf_attr_string(attr.code);
        printf("  Attribute: %s\n", attr_name);

        Dwarf_Word value;
        if (dwarf_formudata(&attr, &value) == 0) {
            printf("    Value: %llu\n", static_cast<unsigned long long>(value));
        } else {
            const char *str_value = dwarf_formstring(&attr);
            if (str_value) {
                printf("    Value: %s\n", str_value);
            }
        }
    }*/
}

//Find the param's die
Dwarf_Die find_param(Dwarf_Die *func, std::string symbol)
{
    Dwarf_Die vardie;

    dwarf_getscopevar (func, 1, symbol.c_str(), 0, NULL, 0, 0, &vardie);

    return vardie;
}

Dwarf_Attribute * find_func_frame_base(Dwarf_Die *func, Dwarf_Attribute *fb_attr_mem)
{
    assert(dwarf_tag(func) == DW_TAG_subprogram);

    Dwarf_Attribute *fb_attr = NULL;
    fb_attr = dwarf_attr_integrate(func, DW_AT_frame_base, fb_attr_mem);
    return fb_attr;
}

VarLocation translate_param_location(Dwarf_Die *func, std::string symbol, Dwarf_Addr pc, Dwarf_Die &vardie)
{
    vardie = find_param(func, symbol);
    Dwarf_Attribute fb_attr_mem;
    Dwarf_Attribute *fb_attr = find_func_frame_base(func, &fb_attr_mem);

    //Assume the vardie must has a DW_AT_location
    Dwarf_Attribute loc_attr;
    dwarf_attr_integrate(&vardie, DW_AT_location, &loc_attr);

    Dwarf_Op *expr;
    size_t len;
    int r = dwarf_getlocation_addr(&loc_attr, pc, &expr, &len, 1);
    if(r != 1 || len <= 0) {
	printf("Get var location expr failed for symbol %s\n", symbol.c_str());
    }

    VarLocation varloc;
    translate_expr(fb_attr, expr, pc, varloc);    
    return varloc;
}

bool func_entrypc(Dwarf_Die *func, Dwarf_Addr *addr)
{
  assert (func);

  *addr = 0;

  if (dwarf_entrypc (func, addr) == 0 && *addr != 0)
    return true;

  Dwarf_Addr start = 0, end;
  if (dwarf_ranges (func, 0, addr, &start, &end) >= 0)
    {
      if (*addr == 0)
	*addr = start;

      return *addr != 0;
    }

  return false;

}

Dwarf_Addr find_prologue(Dwarf_Die *func)
{
  Dwarf_Addr entrypc;
  if (func_entrypc (func, &entrypc) == false)
    printf("error in func_entrypc: %s: %s",
           dwarf_diename (func), dwarf_errmsg (-1));

  int dwbias = 0;
  entrypc += dwbias;

  //printf ("%-16s %lld ", dwarf_diename (func), (long long)entrypc);
 
  //identify whether it's compiled with -O2 -g 
  if(has_loclist())
      return entrypc;

  Dwarf_Addr *bkpts = NULL;
  Dwarf_Addr pc = 0;
  int bcnt = dwarf_entry_breakpoints (func, &bkpts);
  if (bcnt <= 0)
    printf ("\t%s\n", dwarf_errmsg (-1));
  else
  {
      if(bcnt > 1) 
	  printf("Found more than 1 prolgue\n");
      pc = bkpts[0];
      std::cout << "prologue is " << pc << std::endl;
  }
  return pc;
}


static inline void
dwarf_die_type (Dwarf_Die *die, Dwarf_Die *typedie_mem)
{
    Dwarf_Attribute attr_mem, *attr;
    attr = dwarf_attr_integrate (die, DW_AT_type, &attr_mem);
    Dwarf_Die *tmpdie = dwarf_formref_die (attr, typedie_mem);
    if (tmpdie != NULL && dwarf_tag(tmpdie) == DW_TAG_unspecified_type) {
	printf("detects unspecified type\n");
    } else if(tmpdie == NULL) {
	printf("no type dectected");
    }

}

void find_class_member(Dwarf_Die *vardie, 
	               Dwarf_Die *typedie,
		       std::string member, 
		       Dwarf_Attribute *attr)
{
    //TODO deal with inheritance later
    Dwarf_Die die;
    int r = dwarf_child(typedie, &die);
    if (r != 0) {
	printf("dwarf_child no children, unexpected exit");
	return;
    }
    do {
	int tag = dwarf_tag(&die);
        if (tag != DW_TAG_member && tag != DW_TAG_inheritance
            && tag != DW_TAG_enumeration_type)    continue;

        const char *name = dwarf_diename(&die);
	if (tag == DW_TAG_inheritance) {
	    //TODO
	} else if (tag == DW_TAG_enumeration_type)
	{
	    //TODO
	} else if (name == NULL) {
	    //TODO
	} else if (name == member) {
	    *vardie = die;
	}

    } while (dwarf_siblingof(&die, &die) == 0);

    if (dwarf_hasattr_integrate(vardie, DW_AT_data_member_location)) {
	dwarf_attr_integrate(vardie, DW_AT_data_member_location, attr);
    } else if (dwarf_hasattr_integrate(vardie, DW_AT_data_bit_offset)) {
	//TODO deal with bit member
    }

}

void translate_fields(Dwarf_Die *vardie,
	              Dwarf_Die *typedie,
		      Dwarf_Addr pc,
		      std::vector<std::string> fields,
		      std::vector<Field> &res)
{
    int i = 1;
    for (auto x : res) {
	x.pointer = false;
	x.offset = 0;
    }
    while (i < (int)fields.size()) {
	switch (dwarf_tag(typedie)) 
	{
	    
        case DW_TAG_typedef:
        case DW_TAG_const_type:
        case DW_TAG_volatile_type:
        case DW_TAG_restrict_type:
          /* Just iterate on the referent type.  */
          dwarf_die_type (typedie, typedie);
          break;

        case DW_TAG_reference_type:
        case DW_TAG_rvalue_reference_type:
	  res[i].pointer = true;
          dwarf_die_type (typedie, typedie);
          break;
        case DW_TAG_pointer_type:
          /* A pointer with no type is a void* -- can't dereference it. */
          if (!dwarf_hasattr_integrate (typedie, DW_AT_type))
	  {
	      printf("invalid access pointer %s", fields[i].c_str());
	      return;
	  }
	  res[i].pointer = true;
	  dwarf_die_type(typedie, typedie);
	  break;
        case DW_TAG_array_type:
	  //TODO
	  break;
        case DW_TAG_structure_type:
        case DW_TAG_union_type:
        case DW_TAG_class_type:
	{
          if (dwarf_hasattr(typedie, DW_AT_declaration))
          {
              Dwarf_Die *tmpdie = resolve_typedecl(typedie);
              if (tmpdie == NULL) {
	         printf("couldn't resolve type at %s", fields[i].c_str());
		 return;
	      }
               
              *typedie = *tmpdie;
          }
	  Dwarf_Attribute attr;
	  find_class_member(vardie, typedie, fields[i], &attr);
	  Dwarf_Op *expr;
	  size_t len;
	  if (dwarf_getlocation_addr(&attr, pc, &expr, &len, 1) != 1) {
	      printf("failed to get location of attr for %s", fields[i].c_str());
	      return;
	  }
	  VarLocation varloc;
	  translate_expr(NULL,expr, pc, varloc);
	  res[i].offset = varloc.offset;

	  dwarf_die_type(vardie, typedie);
	  ++i;
	}
	break;
        case DW_TAG_enumeration_type:
        case DW_TAG_base_type:
	  printf("invalid access enum or base type %s", fields[i].c_str());
	  break;
	default:
	  printf("unexpected type %s", fields[i].c_str());
	  break;
	}
    }
}

bool filter_func(std::string funcname)
{
    for(auto x : probes) {
	std::size_t found = x.first.find_last_of(":");
	std::string name = x.first.substr(found+1);
	if(funcname == name) 
	    return true;
    }
    return false;
}

bool filter_cu(std::string unitname)
{
    std::size_t found = unitname.find_last_of("/");
    std::string name = unitname.substr(found+1);
    
    for(auto x : probe_units) {
	if(x == name) 
	    return true;
    }
    return false;
}

static int
handle_function(Dwarf_Die *die, void *data)
{
    const char *funcname = dwarf_diename(die); 
    if(!filter_func(funcname))
	return 0;
    Dwarf_Die func_spec = *die;
    if (dwarf_hasattr(die, DW_AT_specification))
    {
	Dwarf_Attribute attr_mem;
	Dwarf_Attribute *tmpattr = dwarf_attr_integrate(die, DW_AT_specification, &attr_mem);
	dwarf_formref_die(tmpattr, &func_spec);
    }
    Dwarf_Die *scopes;
    int nscopes = dwarf_getscopes_die(&func_spec, &scopes);
    
    std::string fullname = funcname;
    if (nscopes > 1)
    {
       fullname = "::" + fullname;
       fullname = dwarf_diename(&scopes[1]) + fullname;
    }

    //printf("function fullname is %s\n", fullname.c_str());
    if(probes.find(fullname) == probes.end()) {
	return 0;
    }
    //TODO need to check if the class name matches
    Dwarf_Addr pc = find_prologue(die);
    func2pc[fullname] =  pc;
    std::vector<VarField> &vf = func2vf[fullname];
    auto arr = probes[fullname];
    vf.resize(arr.size());
    for (int i = 0; i < (int)arr.size(); ++i) {
	std::string varname = arr[i][0];
	Dwarf_Die vardie, typedie;
	VarLocation varloc = translate_param_location(die, varname, pc, vardie);
	//printf("var location : register %d, offset %d, stack %d\n", varloc.reg, varloc.offset, varloc.stack);
	vf[i].varloc = varloc;

	// translate fileds
	dwarf_die_type(&vardie, &typedie);
	vf[i].fields.resize(arr[i].size());
	translate_fields(&vardie, &typedie, pc, arr[i], vf[i].fields);
	for (int j = 1; j < (int)vf[i].fields.size(); ++j) {
	    //printf("Field %s is at offset %d, defref %d\n", arr[i][j].c_str(), vf[i].fields[j].offset, vf[i].fields[j].pointer);
	}
    }
    return 0;
}

static void
translate_expr(Dwarf_Attribute *fb_attr, Dwarf_Op *expr, Dwarf_Addr pc, VarLocation &varloc)
{
    int atom = expr->atom;

    //TODO can put a debug message to print the atom's name in string

    switch(atom) {
	case DW_OP_deref:
        case DW_OP_dup:
        case DW_OP_drop:
        case DW_OP_over:
        case DW_OP_swap:
        case DW_OP_rot:
        case DW_OP_xderef:
        case DW_OP_abs:
        case DW_OP_and:
        case DW_OP_div:
        case DW_OP_minus:
        case DW_OP_mod:
        case DW_OP_mul:
        case DW_OP_neg:
        case DW_OP_not:
        case DW_OP_or:
        case DW_OP_plus:
        case DW_OP_shl:
        case DW_OP_shr:
        case DW_OP_shra:
        case DW_OP_xor:
        case DW_OP_eq:
        case DW_OP_ge:
        case DW_OP_gt:
        case DW_OP_le:
        case DW_OP_lt:
        case DW_OP_ne:
        case DW_OP_lit0 ... DW_OP_lit31:
        case DW_OP_nop:
        case DW_OP_stack_value:
        case DW_OP_form_tls_address:
        /* No arguments. */
          printf ("atom %d ", atom);
          break;

	case DW_OP_bregx:
	   varloc.reg = expr->number;
	   varloc.offset = expr->number2; 
           break;
	
	case DW_OP_breg0 ... DW_OP_breg31:
	   varloc.reg = expr->atom - DW_OP_breg0;
	   varloc.offset = expr->number;
	   break;

        case DW_OP_fbreg:
	   {
	     Dwarf_Op *fb_expr;
	     size_t fb_exprlen;
	     int res = dwarf_getlocation_addr(fb_attr, pc, &fb_expr, &fb_exprlen, 1);
	     if (res != 1) {
	         printf("translate_expr get fb_expr failed\n");
	     }
	   
	     translate_expr(fb_attr, fb_expr, pc, varloc);
	     varloc.offset += expr->number; 
	     varloc.stack = true;
	   }
           break;

	case DW_OP_call_frame_cfa:
	   {
             Dwarf_Op *cfa_ops = NULL;
             size_t cfa_nops = 0;
             // Try .debug_frame first
             Dwarf_Frame *frame = NULL;
             if(cfi_debug != NULL) {
	         if(dwarf_cfi_addrframe(cfi_debug, pc, &frame) == 0) {
	              dwarf_frame_cfa(frame, &cfa_ops, &cfa_nops);
	         } else {
	              printf("dwarf_frame_cfa add debug frame failed\n");
	         }
             }

             if(cfa_ops == NULL) {
	         if(dwarf_cfi_addrframe(cfi_eh, pc, &frame) == 0) {
	              dwarf_frame_cfa(frame, &cfa_ops, &cfa_nops);
	         } else {
	              printf("dwarf_frame_cfa add eh frame failed\n");
	         }
             }

	     translate_expr(fb_attr, cfa_ops, pc, varloc);
	   }
           break;
        case DW_OP_reg0 ... DW_OP_reg31:
	   varloc.reg = expr->atom - DW_OP_reg0;
	   break;
	   
	case DW_OP_plus_uconst:
	   varloc.offset = expr->number;
	   break;

        default:
           break;
    }

}

static Dwfl* create_dwfl (int fd, const char *fname)
{
  int dwfl_fd = dup (fd);
  Dwfl *dwfl = NULL;
  if (dwfl_fd < 0) {
      printf("create_dwfl dup failed\n");
      return 0; 
  }

  static const Dwfl_Callbacks callbacks =
  {
      .find_debuginfo = dwfl_standard_find_debuginfo,
      .section_address = dwfl_offline_section_address
  };
  
  dwfl = dwfl_begin (&callbacks);

  //if(dwfl != NULL)
    //dwfl->offline_next_address = 0;

  if (dwfl_report_offline (dwfl, fname, fname, dwfl_fd) == NULL)
    {
	printf("dwfl_report_offline open dwfl failed");
        close (dwfl_fd);		
        dwfl = NULL;
    }
  else
    dwfl_report_end (dwfl, NULL, NULL);

  return dwfl;
}

static int
handle_module (Dwfl_Module *dwflmod,
	       void **userdata,
	       const char *name,
	       Dwarf_Addr base,
	       void *arg)
{
    assert(dwflmod != NULL);
    Dwarf_Addr modbias;
    Dwarf *dwarf = dwfl_module_getdwarf(dwflmod, &modbias);

    if (!dwarf) {
        printf("handle_module dwarf get error");
        return EXIT_FAILURE;
    }

    int start_time = clock();
    traverse_module(dwflmod, dwarf, iterate_types_in_cu, true);
    int end_process_types_time = clock();

    Dwarf_Off offset = 0;
    Dwarf_Off next_offset;
    size_t header_size;
    Dwarf_Die cu_die;

    while (dwarf_nextcu(dwarf, offset, &next_offset, &header_size, nullptr, nullptr, nullptr) == 0) {
        if (dwarf_offdie(dwarf, offset + header_size, &cu_die) != nullptr) {
	    cfi_debug = dwfl_module_dwarf_cfi (dwflmod, &cfi_debug_bias);
	    cfi_eh = dwfl_module_eh_cfi (dwflmod, &cfi_eh_bias);
	    assert (cfi_debug == NULL || cfi_debug_bias == 0);

	    std::string cu_name = dwarf_diename (&cu_die) ?: "<unknown>";
            if (filter_cu(cu_name)) {
		std::cout << "cu name " << cu_name << std::endl;
	        cur_cu = &cu_die;
                dwarf_getfuncs(&cu_die, &handle_function, NULL, 0);
	    }
        }
        offset = next_offset;
    }
    int end_process_funcs_time = clock();

    std::cout<<"process types take " << (end_process_types_time-start_time)/double(CLOCKS_PER_SEC)*1000 << std::endl; 
    std::cout<<"process functions take " << (end_process_funcs_time - start_time)/double(CLOCKS_PER_SEC)*1000 << std::endl; 
    return 0;
}

int parse_ceph_dwarf(std::string osd_path) {
    const char *fname = osd_path.c_str();
    int fd = open(fname, O_RDONLY);
    if (fd == -1)
    {
	printf("cannot open input file '%s'", fname);
	return 0;
    }
    
    Dwfl *dwfl = create_dwfl (fd, fname);
   
    bool seen = false; 
    dwfl_getmodules(dwfl, handle_module, &seen, 0);
    return 0;
}



int exists(int id)
{
    for (int i = 0; i < num_osd; ++i)
    {
       if (osds[i] == id)
         return 1;
    }
    return 0;
}

int osd_pid_to_id(__u32 pid) 
{
    for (int i = 0; i < num_osd; ++i) {
       if (pids[i] == (int)pid) {
          return osds[i];
       }
    } 
    //First time, read from /proc/<pid>/cmdline
    char path_cmdline[50];
    char pname[200];
    int id = 0;
    memset(path_cmdline, 0, sizeof(path_cmdline));
    snprintf(path_cmdline, sizeof(path_cmdline), "/proc/%d/cmdline", pid);
    int fd = open(path_cmdline, O_RDONLY);
    if(read(fd, pname, 200) >= 0) {
       id = pname[41] - '0';
    }
    close(fd);
    //DEBUG("pid %d, osd_id %d\n", pid, id);
    return id;
}

__u64 to_ns(struct timespec *ts) 
{
   return ts->tv_nsec + (ts->tv_sec * 1000000000ull);
}

__u64 to_us(struct timespec *ts) 
{
   return (ts->tv_nsec / 1000) + (ts->tv_sec * 1000000ull);
}

__u64 to_ms(struct timespec *ts)
{
   return (ts->tv_nsec / 1000000) + (ts->tv_sec * 1000);
}

void timespec_diff(struct timespec *start, struct timespec *stop,
                   struct timespec *result)
{
    if ((stop->tv_nsec - start->tv_nsec) < 0) {
        result->tv_sec = stop->tv_sec - start->tv_sec - 1;
        result->tv_nsec = stop->tv_nsec - start->tv_nsec + 1000000000;
    } else {
        result->tv_sec = stop->tv_sec - start->tv_sec;
        result->tv_nsec = stop->tv_nsec - start->tv_nsec;
    }

    return;
}

__u64 timespec_sub_ms(struct timespec *a, struct timespec *b)
{
   struct timespec c;
   timespec_diff(b, a, &c);
   return to_ms(&c);
}

__u64 get_bootstamp() 
{
	struct timespec realtime, boottime, prevtime;
	clock_gettime( CLOCK_REALTIME, &realtime );
	clock_gettime( CLOCK_BOOTTIME, &boottime );
	timespec_diff(&boottime, &realtime, &prevtime);

	return (prevtime.tv_sec * 1000000000ull) + prevtime.tv_nsec;
} 

static int handle_event(void *ctx, void *data, size_t size)
{
    struct op_v *val = (struct op_v *)data;

    if (val->wb == 0) { // TODO handling read
       return 0;
    }

    int osd_id = osd_pid_to_id(val->pid);
    if (!exists(osd_id)){
       osds[num_osd] = osd_id;
       pids[num_osd++] = val->pid;
    }
    op_stat[osd_id].recv_lat += (val->recv_complete_stamp - val->recv_stamp);
    op_stat[osd_id].max_recv_lat = MAX(op_stat[osd_id].max_recv_lat, (val->recv_complete_stamp - val->recv_stamp));
    op_stat[osd_id].dispatch_lat += (val->enqueue_stamp - (val->recv_complete_stamp - bootstamp) );
    op_stat[osd_id].max_dispatch_lat = MAX(op_stat[osd_id].max_dispatch_lat, (val->enqueue_stamp - (val->recv_complete_stamp - bootstamp) ));
    op_stat[osd_id].queue_lat += (val->dequeue_stamp - val->enqueue_stamp);
    op_stat[osd_id].max_queue_lat = MAX(op_stat[osd_id].max_queue_lat, (val->dequeue_stamp - val->enqueue_stamp));
    op_stat[osd_id].osd_lat += (val->submit_transaction_stamp - val->dequeue_stamp);
    op_stat[osd_id].max_osd_lat = MAX(op_stat[osd_id].max_osd_lat, (val->submit_transaction_stamp - val->dequeue_stamp));
    op_stat[osd_id].bluestore_alloc_lat += (val->data_submit_stamp - val->do_write_stamp);
    op_stat[osd_id].bluestore_data_lat += (val->data_committed_stamp - val->data_submit_stamp);
    op_stat[osd_id].bluestore_kv_lat += (val->kv_committed_stamp - val->kv_submit_stamp);
    op_stat[osd_id].bluestore_lat += (val->reply_stamp - val->submit_transaction_stamp);
    op_stat[osd_id].max_bluestore_lat = MAX(op_stat[osd_id].max_bluestore_lat, (val->reply_stamp - val->submit_transaction_stamp));
    op_stat[osd_id].op_lat += (val->reply_stamp - (val->recv_stamp - bootstamp));
    op_stat[osd_id].max_op_lat = MAX(op_stat[osd_id].max_op_lat,  (val->reply_stamp - (val->recv_stamp - bootstamp)));
    op_stat[osd_id].r_cnt += (val->rb ? 1 : 0);
    op_stat[osd_id].w_cnt += (val->wb ? 1 : 0);
    op_stat[osd_id].rbytes += val->rb;
    op_stat[osd_id].wbytes += val->wb;
    //printf("Number is %lld Client.%lld tid %lld recv_stamp %lld recv_complete_stamp %lld dispatch_stamp %lld enqueue_stamp %lld dequeue_stamp %lld execute_ctx_stamp %lld submit_transaction %lld do_write_stamp %lld wctx_finish_stamp %lld data_submit_stamp %lld data_committed_stamp %lld kv_submit_stamp %lld kv_committed_stamp %lld reply_stamp %lld write_bytes %lld read_bytes %lld\n",cnt, val->owner, val->tid, val->recv_stamp-bootstamp, val->recv_complete_stamp-bootstamp, val->dispatch_stamp-bootstamp, val->enqueue_stamp, val->dequeue_stamp, val->execute_ctx_stamp, val->submit_transaction_stamp, val->do_write_stamp, val->wctx_finish_stamp, val->data_submit_stamp, val->data_committed_stamp, val->kv_submit_stamp, val->kv_committed_stamp, val->reply_stamp, val->wb, val->rb);
    struct timespec now;
    clock_gettime(CLOCK_BOOTTIME, &now);
    __u64 interval = timespec_sub_ms(&now, &lasttime);    
    if(interval >= period * 1000) {
       int interval_s = MAX(1, interval / 1000);
       if (period > 0) 
	       printf("OSD  r/s    w/s    rkB/s    wkB/s     rcv_lat     disp_lat      qu_lat      osd_lat   bs_alloc_lat    bs_data_lat      bs_kv_lat        op_lat\n");
       for (int i = 0; i < num_osd; ++i) {
         osd_id = osds[i];
         cnt = op_stat[osd_id].w_cnt + op_stat[osd_id].r_cnt;
	 if(cnt == 0 && period == 0) 
	    continue;
	 cnt = MAX(cnt, 1);
         printf("%3d %4lld%7lld%9lld%9lld%12.3f%13.3f%12.3f%13.3f%15.3f%15.3f%15.3f%14.3f \n", 
			osd_id,
                        op_stat[osd_id].r_cnt/interval_s, op_stat[osd_id].w_cnt/interval_s, 
                        op_stat[osd_id].rbytes/interval_s/1024, op_stat[osd_id].wbytes/interval_s/1024, 
                        mode == MODE_AVG ? (op_stat[osd_id].recv_lat/cnt / 1000.0) : (op_stat[osd_id].max_recv_lat / 1000.0), 
			mode == MODE_AVG ? (op_stat[osd_id].dispatch_lat/cnt / 1000.0) : (op_stat[osd_id].max_dispatch_lat / 1000.0), 
                        mode == MODE_AVG ? (op_stat[osd_id].queue_lat/cnt / 1000.0) : (op_stat[osd_id].max_queue_lat / 1000.0), 
			mode == MODE_AVG ? (op_stat[osd_id].osd_lat/cnt / 1000.0) : (op_stat[osd_id].max_osd_lat / 1000.0),
			mode == MODE_AVG ? (op_stat[osd_id].bluestore_alloc_lat/cnt / 1000.0) : 0,
			mode == MODE_AVG ? (op_stat[osd_id].bluestore_data_lat/cnt / 1000.0) : 0,
			mode == MODE_AVG ? (op_stat[osd_id].bluestore_kv_lat/cnt / 1000.0) : 0,
                        //mode == MODE_AVG ? (op_stat[osd_id].bluestore_lat/cnt / 1000.0) : (op_stat[osd_id].max_bluestore_lat / 1000.0),
			mode == MODE_AVG ? (op_stat[osd_id].op_lat/cnt / 1000.0) : (op_stat[osd_id].max_op_lat / 1000.0) );
         memset(&op_stat[osd_id], 0, sizeof(op_stat[osd_id]));
       }
       if (period > 0)
          printf("\n\n");
       lasttime = now;
    }
    
    //printf("Number is %lld Client.%lld tid %lld recv_stamp %lld recv_complete_stamp %lld dispatch_stamp %lld enqueue_stamp %lld dequeue_stamp %lld execute_ctx_stamp %lld submit_transaction %lld reply_stamp %lld write_bytes %lld read_bytes %lld\n",cnt, val->owner, val->tid, val->recv_stamp-bootstamp, val->recv_complete_stamp-bootstamp, val->dispatch_stamp-bootstamp, val->enqueue_stamp, val->dequeue_stamp, val->execute_ctx_stamp, val->submit_transaction_stamp, val->reply_stamp, val->wb, val->rb);
    //printf("The current number is %lld Client.%lld tid %lld enqueue_stamp %lld dequeue_stamp %lld\n",cnt, val->owner, val->tid, val->enqueue_stamp, val->dequeue_stamp);
    
    return 0;
}

/*
static void handle_lost_event(void *ctx, int cpu, __u64 lost_cnt)
{
	printf("lost %llu events on cpu %d\n", lost_cnt, cpu);
}
*/

int parse_args(int argc, char **argv)
{
    char opt;
    while ((opt = getopt(argc, argv, ":d:m:")) != -1) 
    {
	switch (opt) 
        {
	    case 'd':
		period = optarg[0] - '0';
                break;
            case 'm':
		if(0 == strcmp(optarg, "avg")) {
		    mode = MODE_AVG;
		} else if(0 == strcmp(optarg, "max")) {
		    mode = MODE_MAX;
		} else {
		    printf("Unknown mode\n");
		    return -1;
		}
                break;
	    case '?':
		printf("Unknown option: %c \n ", optopt);
	        return -1;
	    case ':':
		printf("Missing arg for %c \n", optopt);
	        return -1;
        }
    }
    return 0;
}

void fill_map_hprobes(struct bpf_map *hprobes)
{
    for(auto x : func2vf)
    {
	
	std::string funcname = x.first;
        int key_idx = func_id[funcname];
	for (auto vf : x.second) 
	{
	   struct VarField_Kernel vfk;
	   vfk.varloc = vf.varloc;
	   printf("fill_map_hprobes: function %s var location : register %d, offset %d, stack %d\n", funcname.c_str(), vfk.varloc.reg, vfk.varloc.offset, vfk.varloc.stack);
	   vfk.size = vf.fields.size();
	   for (int i = 0; i < vfk.size; ++i) {
	       vfk.fields[i] = vf.fields[i];
	   }
	   bpf_map__update_elem(hprobes, &key_idx, sizeof(key_idx), &vfk, sizeof(vfk), 0);
	   ++key_idx;
	}
    }
}
    
int main(int argc, char **argv)
{
    
        if(parse_args(argc, argv) < 0)
	    return 0;

        struct uprobe_osd_bpf *skel;
        //long uprobe_offset;
        int ret=0;
	struct ring_buffer *rb;

	DEBUG("Start to parse ceph dwarf info\n");

	//parse_ceph_dwarf("/usr/bin/ceph-osd");
	parse_ceph_dwarf("/home/taodd/Git/ceph/build/bin/ceph-osd");

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Load and verify BPF application */
	DEBUG("Start to load uprobe\n");

	skel = uprobe_osd_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	//map_fd = bpf_object__find_map_fd_by_name(skel->obj, "hprobes");

	fill_map_hprobes(skel->maps.hprobes);

	/* Attach tracepoint handler */
	DEBUG("BPF prog loaded\n");

        size_t enqueue_op_addr = func2pc["OSD::enqueue_op"];	
	struct bpf_link *ulink = bpf_program__attach_uprobe(skel->progs.uprobe_enqueue_op,
							    false /* not uretprobe */,
							    //176928 /* self pid */,
							    -1,
							    //"/usr/bin/ceph-osd",
							    "/home/taodd/Git/ceph/build/bin/ceph-osd",
							    enqueue_op_addr);
	if (!ulink) {
		DEBUG("Failed to attach uprobe to uprobe_dequeue_op\n");
		return -errno;
	}
	
	DEBUG("uprobe_enqueue_op attached\n");	

	__u64 dequeue_op_addr = func2pc["OSD::dequeue_op"];
	ulink = bpf_program__attach_uprobe(skel->progs.uprobe_dequeue_op,
							    false ,
							    -1,
							   //176928,
							    //"/usr/bin/ceph-osd",
							    "/home/taodd/Git/ceph/build/bin/ceph-osd",
							    dequeue_op_addr);
	
	DEBUG("uprobe_dequeue_op attached\n");	

	if (!ulink) {
		DEBUG("Failed to attach uprobe to uprobe_dequeue_op\n");
		return -errno;
	}

	__u64 execute_ctx_addr = func2pc["PrimaryLogPG::execute_ctx"];
	ulink = bpf_program__attach_uprobe(skel->progs.uprobe_execute_ctx,
							    false ,
							    -1,
							    //176928,
							    //"/usr/bin/ceph-osd",
							    "/home/taodd/Git/ceph/build/bin/ceph-osd",
							    execute_ctx_addr);
	
	DEBUG("uprobe_execute_ctx attached\n");	

	if (!ulink) {
		DEBUG("Failed to attach uprobe to uprobe_execute_ctx\n");
		return -errno;
	}
	
	__u64 submit_transaction_addr = func2pc["ReplicatedBackend::submit_transaction"];
	ulink = bpf_program__attach_uprobe(skel->progs.uprobe_submit_transaction,
							    false,
							    //176928,
							    -1,
							    //"/usr/bin/ceph-osd",
							    "/home/taodd/Git/ceph/build/bin/ceph-osd",
							    submit_transaction_addr);
	
	if (!ulink) {
		DEBUG("Failed to attach uprobe to uprobe_submit_transaction\n");
		return -errno;
	}
	DEBUG("uprobe_submit_transaction attached\n");	
	
	__u64 log_op_stats_addr = func2pc["PrimaryLogPG::log_op_stats"];
	ulink = bpf_program__attach_uprobe(skel->progs.uprobe_log_op_stats,
							    false ,
							    //176928 ,
							    -1,
							    //"/usr/bin/ceph-osd",
							    "/home/taodd/Git/ceph/build/bin/ceph-osd",
							    log_op_stats_addr);
	
	if (!ulink) {
		DEBUG("Failed to attach uprobe to log_op_stats\n");
		return -errno;
	}

	DEBUG("uprobe_log_op_stats attached\n");	


	__u64 do_write_addr = func2pc["BlueStore::_do_write"];
	ulink = bpf_program__attach_uprobe(skel->progs.uprobe_do_write,
							    false ,
							    //176928 ,
							    -1,
							    //"/usr/bin/ceph-osd",
							    "/home/taodd/Git/ceph/build/bin/ceph-osd",
							    do_write_addr);
	
	if (!ulink) {
		DEBUG("Failed to attach uprobe to do_write_addr\n");
		return -errno;
	}
	DEBUG("uprobe_do_write attached\n");	

	__u64 wctx_finish_addr = func2pc["BlueStore::_wctx_finish"];
	ulink = bpf_program__attach_uprobe(skel->progs.uprobe_wctx_finish,
							    false ,
							    //176928 ,
							    -1,
							    //"/usr/bin/ceph-osd",
							    "/home/taodd/Git/ceph/build/bin/ceph-osd",
							    wctx_finish_addr);
	
	if (!ulink) {
		DEBUG("Failed to attach uprobe to wctx_finish_addr\n");
		return -errno;
	}
	DEBUG("uprobe_wctx_finish attached\n");	

	__u64 txc_state_proc_addr = func2pc["BlueStore::_txc_state_proc"];
	ulink = bpf_program__attach_uprobe(skel->progs.uprobe_txc_state_proc,
							    false ,
							    //176928 ,
							    -1,
							    //"/usr/bin/ceph-osd",
							    "/home/taodd/Git/ceph/build/bin/ceph-osd",
							    txc_state_proc_addr);
	
	if (!ulink) {
		DEBUG("Failed to attach uprobe to txc_state_proc_addr\n");
		return -errno;
	}
	DEBUG("uprobe_txc_state_proc attached\n");	

	__u64 txc_apply_kv_addr = func2pc["BlueStore::_txc_apply_kv"];
	ulink = bpf_program__attach_uprobe(skel->progs.uprobe_txc_apply_kv,
							    false ,
							    //176928 ,
							    -1,
							    //"/usr/bin/ceph-osd",
							    "/home/taodd/Git/ceph/build/bin/ceph-osd",
							    txc_apply_kv_addr);
	
	if (!ulink) {
		DEBUG("Failed to attach uprobe to txc_apply_kv\n");
		return -errno;
	}
	DEBUG("uprobe_txc_apply_kv attached\n");	

	bootstamp = get_bootstamp();
	DEBUG("New a ring buffer\n");
	
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if(!rb) {
		printf("failed to setup ring_buffer\n");
		goto cleanup;
	}

	DEBUG("Started to poll from ring buffer\n");

	clock_gettime(CLOCK_BOOTTIME, &lasttime);
	memset(op_stat, 0, MAX_OSD * sizeof(op_stat[0]));

	while ((ret = ring_buffer__poll(rb, 1000)) >= 0) {
		
        }


	/* we can also attach uprobe/uretprobe to any existing or future
	 * processes that use the same binary executable; to do that we need
	 * to specify -1 as PID, as we do here
	 */
	/* Let libbpf perform auto-attach for uprobe_sub/uretprobe_sub
	 * NOTICE: we provide path and symbol info in SEC for BPF programs
	 */
	DEBUG("Unexpected line hit\n");
        sleep(600);
cleanup:
	printf("Clean up the eBPF program\n");
	ring_buffer__free(rb);
	uprobe_osd_bpf__destroy(skel);
	return -errno;
}
