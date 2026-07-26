#include <bpf/libbpf.h>
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <sys/resource.h>
#include <time.h>

#include <cassert>
#include <cstring>
#include <ctime>
#include <iostream>
#include <limits>
#include <map>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>
#include <queue>
#include <fstream>

#include "osdtrace.skel.h"
extern "C" {
#include <dwarf.h>
#include <elf.h>
#include <elfutils/libdw.h>
#include <elfutils/libdwfl.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
}
#include "bpf_ceph_types.h"
#include "dwarf_parser.h"
#include "embedded_dwarf_data.h"
#include "utils.h"
#include "version_utils.h"

using namespace std;

bool DwarfParser::die_has_loclist(Dwarf_Die *begin_die) {
  Dwarf_Die die;
  Dwarf_Attribute loc;

  if (dwarf_child(begin_die, &die) != 0) return false;

  do {
    switch (dwarf_tag(&die)) {
      case DW_TAG_formal_parameter:
      case DW_TAG_variable:
        if (dwarf_attr_integrate(&die, DW_AT_location, &loc) &&
            dwarf_whatform(&loc) == DW_FORM_sec_offset)
          return true;
        break;
      default:
        if (dwarf_haschildren(&die))
          if (die_has_loclist(&die)) return true;
        break;
    }
  } while (dwarf_siblingof(&die, &die) == 0);

  return false;
}

bool DwarfParser::has_loclist() {
  assert(cur_cu);
  return die_has_loclist(cur_cu);
}

bool DwarfParser::func_entrypc(Dwarf_Die *func, Dwarf_Addr *addr) {
  assert(func);

  *addr = 0;

  if (dwarf_entrypc(func, addr) == 0 && *addr != 0) return true;

  Dwarf_Addr start = 0, end;
  if (dwarf_ranges(func, 0, addr, &start, &end) >= 0) {
    if (*addr == 0) *addr = start;

    return *addr != 0;
  }

  return false;
}

Dwarf_Die *DwarfParser::resolve_typedecl(Dwarf_Die *type) {
  const char *name = dwarf_diename(type);
  if (!name) return NULL;

  string type_name = cache_type_prefix(type) + string(name);

  for (auto &p : global_type_cache) {
    auto &cus = p.second;
    for (auto i = cus.begin(); i != cus.end(); ++i) {
      auto &v = (*i).second;
      if (v.find(type_name) != v.end()) return &(v[type_name]);
    }
  }

  cerr << "Couldn't resolve type " << type_name << endl; 

  return NULL;
}

Dwarf_Die *DwarfParser::resolve_type_name(const std::string& name) {
  const std::string candidates[] = {
      name, "struct " + name, "union " + name, "enum " + name};

  for (auto &module : global_type_cache) {
    for (auto &cu : module.second) {
      for (const auto& candidate : candidates) {
        auto found = cu.second.find(candidate);
        if (found != cu.second.end()) {
          return &found->second;
        }
      }
    }
  }

  cerr << "Couldn't resolve type " << name << endl;
  return NULL;
}

void DwarfParser::request_type_size(const std::string& name) {
  requested_type_sizes.insert(name);
}

int DwarfParser::get_type_size(const std::string& module,
                               const std::string& name) const {
  auto module_it = mod_type_sizes.find(get_basename(module));
  if (module_it == mod_type_sizes.end())
    return -1;
  auto type_it = module_it->second.find(name);
  return type_it == module_it->second.end()
             ? -1
             : static_cast<int>(type_it->second);
}

int DwarfParser::resolve_type_size(Dwfl_Module *module,
                                   const std::string& name) {
  auto module_it = global_type_cache.find(module);
  if (module_it == global_type_cache.end())
    return -1;

  const std::string candidates[] = {
      name, "struct " + name, "union " + name, "enum " + name};
  Dwarf_Die *type = nullptr;
  for (auto& cu : module_it->second) {
    for (const auto& candidate : candidates) {
      auto found = cu.second.find(candidate);
      if (found != cu.second.end()) {
        type = &found->second;
        break;
      }
    }
    if (type != nullptr)
      break;
  }
  if (type == nullptr)
    return -1;

  Dwarf_Die current = *type;
  while (dwarf_tag(&current) == DW_TAG_typedef ||
         dwarf_tag(&current) == DW_TAG_const_type ||
         dwarf_tag(&current) == DW_TAG_volatile_type ||
         dwarf_tag(&current) == DW_TAG_restrict_type) {
    Dwarf_Die referent;
    dwarf_die_type(&current, &referent);
    current = referent;
  }

  Dwarf_Word size = 0;
  if (dwarf_aggregate_size(&current, &size) != 0 ||
      size > std::numeric_limits<uint32_t>::max())
    return -1;
  return static_cast<int>(size);
}

const char *DwarfParser::cache_type_prefix(Dwarf_Die *type) {
  switch (dwarf_tag(type)) {
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

int DwarfParser::iterate_types_in_cu(mod_cu_type_cache_t & mcu, Dwarf_Die *cu_die) {
  assert(cu_die);
  assert(dwarf_tag(cu_die) == DW_TAG_compile_unit ||
         dwarf_tag(cu_die) == DW_TAG_type_unit ||
         dwarf_tag(cu_die) == DW_TAG_partial_unit);

  if (dwarf_tag(cu_die) == DW_TAG_partial_unit) return DWARF_CB_OK;

  cu_type_cache_t &v = mcu[cu_die->addr];
  // TODO inner types process
  // bool has_inner_types = dwarf_srclang(cu_die) == DW_LANG_C_plus_plus;

  int rc = DWARF_CB_OK;
  Dwarf_Die die;

  if (dwarf_child(cu_die, &die) != 0) return rc;

  do
    /* We're only currently looking for named types,
     * although other types of declarations exist */
    switch (dwarf_tag(&die)) {
      case DW_TAG_base_type:
      case DW_TAG_enumeration_type:
      case DW_TAG_structure_type:
      case DW_TAG_class_type:
      case DW_TAG_typedef:
      case DW_TAG_union_type: {
        const char *name = dwarf_diename(&die);
        if (!name || dwarf_hasattr(&die, DW_AT_declaration)
            /*TODO || has_only_decl_members(die)*/)
          continue;
        string type_name = cache_type_prefix(&die) + string(name);
        if (v.find(type_name) == v.end()) v[type_name] = die;

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

void DwarfParser::traverse_module(Dwfl_Module *mod, Dwarf *dw, bool want_type) {
  assert(dw && mod);

  Dwarf_Off off = 0;
  size_t cuhl;
  Dwarf_Off noff;

  mod_cu_type_cache_t &mcu = global_type_cache[mod];
  while (dwarf_nextcu(dw, off, &noff, &cuhl, NULL, NULL, NULL) == 0) {
    Dwarf_Die die_mem;
    Dwarf_Die *die;
    die = dwarf_offdie(dw, off + cuhl, &die_mem);
    string cu_name = dwarf_diename(die) ?: "<unknown>";
    //cout << "preprocess_module cu name " << cu_name << endl;
    /* Skip partial units. */
    if (dwarf_tag(die) == DW_TAG_compile_unit) {
      iterate_types_in_cu(mcu, die);
    }
    off = noff;
  }

  if (want_type) {
    // Process type units.
    Dwarf_Off off = 0;
    size_t cuhl;
    Dwarf_Off noff;
    uint64_t type_signature;
    while (dwarf_next_unit(dw, off, &noff, &cuhl, NULL, NULL, NULL, NULL,
                           &type_signature, NULL) == 0) {
      Dwarf_Die die_mem;
      Dwarf_Die *die;
      die = dwarf_offdie_types(dw, off + cuhl, &die_mem);
      if (dwarf_tag(die) == DW_TAG_type_unit) iterate_types_in_cu(mcu, die);
      off = noff;
    }
  }
}

bool DwarfParser::find_param(Dwarf_Die *func, string symbol,
                             Dwarf_Die &vardie) {
  // dwarf_getscopevar: returns a non-negative scope index on success, -1 on
  // error or -2 when no matching variable exists.  On failure it leaves
  // vardie untouched, so the caller must not use it.
  return dwarf_getscopevar(func, 1, symbol.c_str(), 0, NULL, 0, 0, &vardie) >= 0;
}

Dwarf_Attribute *DwarfParser::find_func_frame_base(
    Dwarf_Die *func, Dwarf_Attribute *fb_attr_mem) {
  assert(dwarf_tag(func) == DW_TAG_subprogram);

  Dwarf_Attribute *fb_attr = NULL;
  fb_attr = dwarf_attr_integrate(func, DW_AT_frame_base, fb_attr_mem);
  return fb_attr;
}

// --- SysV-AMD64 incoming-argument classification ---------------------------
//
// Used only as a fallback when a parameter's DW_AT_location is missing.  We
// reconstruct where the argument lives at function entry from the calling
// convention.  Only the INTEGER and (stack) MEMORY classes are handled — the
// classes osdtrace's traced parameters actually use (pointers, references,
// integers/enums, and large by-value aggregates such as osd_reqid_t).  Any
// parameter we cannot classify with confidence makes the whole fallback bail,
// so we never emit a guessed-wrong location.
namespace {
enum AbiClass { ABI_INTEGER, ABI_MEMORY, ABI_UNHANDLED };

// Peel typedef/const/volatile/restrict down to the underlying type DIE.
bool peel_type(Dwarf_Die *t) {
  for (;;) {
    switch (dwarf_tag(t)) {
      case DW_TAG_typedef:
      case DW_TAG_const_type:
      case DW_TAG_volatile_type:
      case DW_TAG_restrict_type: {
        Dwarf_Attribute a;
        if (dwarf_attr_integrate(t, DW_AT_type, &a) == NULL) return false;
        if (dwarf_formref_die(&a, t) == NULL) return false;
        break;
      }
      default:
        return true;
    }
  }
}

// Classify a parameter by its type DIE.  Returns false if the type cannot be
// resolved (caller treats that as ABI_UNHANDLED / bail).
AbiClass classify_param(Dwarf_Die *param, Dwarf_Word &size) {
  Dwarf_Attribute ta;
  Dwarf_Die t;
  if (dwarf_attr_integrate(param, DW_AT_type, &ta) == NULL) return ABI_UNHANDLED;
  if (dwarf_formref_die(&ta, &t) == NULL) return ABI_UNHANDLED;
  if (!peel_type(&t)) return ABI_UNHANDLED;

  switch (dwarf_tag(&t)) {
    case DW_TAG_pointer_type:
    case DW_TAG_reference_type:
    case DW_TAG_rvalue_reference_type:
    case DW_TAG_enumeration_type:
      size = 8;
      return ABI_INTEGER;

    case DW_TAG_base_type: {
      Dwarf_Attribute ea;
      Dwarf_Word enc = 0;
      if (dwarf_attr_integrate(&t, DW_AT_encoding, &ea) != NULL)
        dwarf_formudata(&ea, &enc);
      // Floats go in SSE registers — not handled here.
      if (enc == DW_ATE_float || enc == DW_ATE_complex_float) return ABI_UNHANDLED;
      Dwarf_Word sz = 0;
      if (dwarf_aggregate_size(&t, &sz) != 0 || sz > 8) return ABI_UNHANDLED;
      size = sz;
      return ABI_INTEGER;
    }

    case DW_TAG_structure_type:
    case DW_TAG_class_type:
    case DW_TAG_union_type:
    case DW_TAG_array_type: {
      Dwarf_Word sz = 0;
      if (dwarf_aggregate_size(&t, &sz) != 0) return ABI_UNHANDLED;
      // Aggregates > 16 bytes are MEMORY class (passed on the stack).  Smaller
      // ones need eightbyte field classification (INTEGER/SSE) — bail.
      if (sz > 16) {
        size = sz;
        return ABI_MEMORY;
      }
      return ABI_UNHANDLED;
    }

    default:
      return ABI_UNHANDLED;
  }
}
}  // namespace

bool DwarfParser::abi_stack_location(Dwarf_Die *func, Dwarf_Addr pc,
                                     long cfa_off, VarLocation &varloc) {
  // Resolve the call-frame CFA at pc into a (reg, offset) pair, then add the
  // argument's CFA-relative offset.  Identical machinery to DW_OP_fbreg.
  Dwarf_Attribute fb_mem;
  Dwarf_Attribute *fb = find_func_frame_base(func, &fb_mem);
  if (fb == NULL) {
    cerr << "abi_stack_location: function has no frame base" << endl;
    return false;
  }
  Dwarf_Op *fb_expr;
  size_t fb_len;
  if (dwarf_getlocation_addr(fb, pc, &fb_expr, &fb_len, 1) != 1 || fb_len == 0) {
    cerr << "abi_stack_location: frame base expr failed" << endl;
    return false;
  }
  if (!translate_expr(fb, fb_expr, pc, varloc)) return false;
  varloc.offset += cfa_off;
  varloc.stack = true;
  return true;
}

bool DwarfParser::abi_param_location(Dwarf_Die *func, Dwarf_Die &target,
                                     Dwarf_Addr pc, VarLocation &varloc) {
#if !defined(__x86_64__)
  // Everything below encodes the SysV-AMD64 calling convention (INTEGER
  // register order, MEMORY-class stack layout); on any other architecture
  // those register numbers and offsets would be wrong (e.g. DWARF regnum 5
  // is RDI on x86-64 but x5 on arm64).  osdtrace/radostrace always run
  // natively on the host they trace, so a non-x86-64 build can never face an
  // x86-64 target: decline the recovery and let the caller fail gracefully.
  (void)func; (void)target; (void)pc; (void)varloc;
  return false;
#else
  // SysV-AMD64 INTEGER argument registers, in order, as DWARF register
  // numbers: RDI=5, RSI=4, RDX=1, RCX=2, R8=8, R9=9.
  static const int kIntArgRegs[6] = {5, 4, 1, 2, 8, 9};
  int int_regs_used = 0;
  long stack_off = 0;  // CFA-relative offset of the next stack argument
  Dwarf_Off target_off = dwarf_dieoffset(&target);

  Dwarf_Die child;
  if (dwarf_child(func, &child) != 0) {
    cerr << "abi_param_location: function has no children" << endl;
    return false;
  }
  do {
    if (dwarf_tag(&child) != DW_TAG_formal_parameter) continue;

    Dwarf_Word size = 0;
    AbiClass cls = classify_param(&child, size);
    if (cls == ABI_UNHANDLED) {
      cerr << "abi_param_location: unhandled parameter class; cannot recover "
              "location" << endl;
      return false;  // safety net: never guess
    }

    bool is_target = (dwarf_dieoffset(&child) == target_off);

    if (cls == ABI_INTEGER) {
      if (int_regs_used < 6) {
        if (is_target) {
          varloc.reg = kIntArgRegs[int_regs_used];
          varloc.offset = 0;
          varloc.stack = false;
          return true;
        }
        ++int_regs_used;
      } else {  // overflowed to the stack, one eightbyte
        if (is_target) return abi_stack_location(func, pc, stack_off, varloc);
        stack_off += 8;
      }
    } else {  // ABI_MEMORY: always on the stack, size rounded up to 8 bytes
      if (is_target) return abi_stack_location(func, pc, stack_off, varloc);
      stack_off += (long)((size + 7) & ~(Dwarf_Word)7);
    }
  } while (dwarf_siblingof(&child, &child) == 0);

  cerr << "abi_param_location: target parameter not found among formals" << endl;
  return false;
#endif  // __x86_64__
}

bool DwarfParser::translate_param_location(Dwarf_Die *func, string symbol,
                                           Dwarf_Addr pc, Dwarf_Die &vardie,
                                           VarLocation &varloc) {
  if (!find_param(func, symbol, vardie)) {
    cerr << "Couldn't find parameter " << symbol << endl;
    return false;
  }

  Dwarf_Attribute loc_attr;
  if (dwarf_attr_integrate(&vardie, DW_AT_location, &loc_attr) == NULL) {
    // The compiler emitted no location for this parameter.  This happens for
    // forwarded by-value aggregates under -march=x86-64-v3 (e.g. reqid in
    // ReplicatedBackend::submit_transaction on Ubuntu amd64v3 / CentOS el10):
    // the value is still at its ABI incoming-argument slot, so recover it from
    // the SysV-AMD64 calling convention instead of giving up.
    if (abi_param_location(func, vardie, pc, varloc)) {
      cerr << "Recovered ABI incoming location for parameter " << symbol << endl;
      return true;
    }
    cerr << "Parameter " << symbol << " has no DW_AT_location" << endl;
    return false;
  }

  Dwarf_Op *expr;
  size_t len;
  int r = dwarf_getlocation_addr(&loc_attr, pc, &expr, &len, 1);
  if (r != 1 || len == 0) {
    cerr << "Get param location expr failed for symbol " << symbol << endl;
    return false;
  }

  Dwarf_Attribute fb_attr_mem;
  Dwarf_Attribute *fb_attr = find_func_frame_base(func, &fb_attr_mem);
  return translate_expr(fb_attr, expr, pc, varloc);
}

bool DwarfParser::find_prologue(Dwarf_Die *func, Dwarf_Addr &pc) {
  Dwarf_Addr entrypc;
  string funcname = dwarf_diename(func);
  if (func_entrypc(func, &entrypc) == false) {
    cerr << "Empty in func_entrypc " << funcname << endl;
    return false;
  }

  int dwbias = 0;
  entrypc += dwbias;

  // identify whether it's compiled with -O2 -g
  if (has_loclist()) {
    pc = entrypc;
    return true;
  }

  Dwarf_Addr *bkpts = NULL;
  int bcnt = dwarf_entry_breakpoints(func, &bkpts);
  if (bcnt <= 0) {
    cerr << "Couldn't found prologue for function " << funcname << endl;
    return false;
  }

  if (bcnt > 1) {
    cout << "Found more than 1 prologue for function " << funcname << endl;
  }
  pc = bkpts[0];
  cout << "prologue is " << pc << endl;
  return true;
}

void DwarfParser::dwarf_die_type(Dwarf_Die *die, Dwarf_Die *typedie_mem) {
  Dwarf_Attribute attr_mem, *attr;
  attr = dwarf_attr_integrate(die, DW_AT_type, &attr_mem);
  Dwarf_Die *tmpdie = dwarf_formref_die(attr, typedie_mem);
  if (tmpdie != NULL && dwarf_tag(tmpdie) == DW_TAG_unspecified_type) {
    cout << "detects unspecified type" << endl;
  } else if (tmpdie == NULL) {
    cerr << "no type dectected" << endl;
  }
}

Dwarf_Die * DwarfParser::dwarf_attr_die(Dwarf_Die *die, unsigned int attr_flag, Dwarf_Die *result)
{
  Dwarf_Attribute attr_mem, *attr;
  attr = dwarf_attr_integrate(die, attr_flag, &attr_mem);
  if (dwarf_formref_die (attr, result) != NULL)
    {
      /* Get the actual DIE type*/
      if (attr_flag == DW_AT_type)
        {
          Dwarf_Attribute sigm;
          Dwarf_Attribute *sig = dwarf_attr (result, DW_AT_signature, &sigm);
          if (sig != NULL)
            result = dwarf_formref_die (sig, result);

          /* A DW_AT_signature might point to a type_unit, then
             the actual type DIE we want is the first child.  */
          if (result != NULL && dwarf_tag (result) == DW_TAG_type_unit)
            dwarf_child (result, result);
        }
      return result;
    }
  return NULL;
}

bool DwarfParser::find_class_member(Dwarf_Die *vardie, Dwarf_Die *typedie,
                                    string member, Dwarf_Attribute *attr) {
  // TODO deal with inheritance later

  std::queue<Dwarf_Die> die_queue;
  die_queue.push(*typedie);
  bool found = false;
  while (!die_queue.empty()) {
    Dwarf_Die die;
    int r = dwarf_child(&die_queue.front(), &die);
    if (r != 0) {
      cerr << "the class " << dwarf_diename(typedie)
           << " has no children, unexpected; skipping" << endl;
      return false;
    }
    do {
      int tag = dwarf_tag(&die);
      if (tag != DW_TAG_member && tag != DW_TAG_inheritance &&
          tag != DW_TAG_enumeration_type)
        continue;

      const char *name = dwarf_diename(&die);
      if (tag == DW_TAG_inheritance) {
        Dwarf_Die inheritee;
        if (dwarf_attr_die (&die, DW_AT_type, &inheritee))
          die_queue.push(inheritee);
      } else if (tag == DW_TAG_enumeration_type) {
        // TODO
      } else if (name == NULL) {
        // TODO
      } else if (name == member) {
        *vardie = die;
        found = true;
        break;
      }

    } while (dwarf_siblingof(&die, &die) == 0);
    die_queue.pop();
    if (found)
      break;
  }

  if (!found) {
    cerr << "couldn't find member " << member << endl;
    return false;
  }
  if (dwarf_hasattr_integrate(vardie, DW_AT_data_member_location)) {
    dwarf_attr_integrate(vardie, DW_AT_data_member_location, attr);
    return true;
  }
  // DW_AT_data_bit_offset (bitfield) is not handled yet; report failure
  // instead of leaving attr unset for the caller to dereference.
  return false;
}

bool DwarfParser::translate_fields(Dwarf_Die *vardie, Dwarf_Die *typedie,
                                   Dwarf_Addr pc, vector<string> fields,
                                   vector<Field> &res) {
  int i = 1;
  Field field = {0, false};
  res.clear();
  res.push_back({0, false});
  while (i < (int)fields.size()) {
    // A cast token changes only the DWARF type used to resolve subsequent
    // members. The following real field retains the pointer dereference.
    static const std::string cast_prefix = "cast:";
    if (fields[i].compare(0, cast_prefix.size(), cast_prefix) == 0) {
      while (dwarf_tag(typedie) == DW_TAG_typedef ||
             dwarf_tag(typedie) == DW_TAG_const_type ||
             dwarf_tag(typedie) == DW_TAG_volatile_type ||
             dwarf_tag(typedie) == DW_TAG_restrict_type) {
        dwarf_die_type(typedie, typedie);
      }
      if (dwarf_tag(typedie) != DW_TAG_pointer_type &&
          dwarf_tag(typedie) != DW_TAG_reference_type &&
          dwarf_tag(typedie) != DW_TAG_rvalue_reference_type) {
        clog << "invalid cast from non-pointer type at " << fields[i] << endl;
        return false;
      }

      Dwarf_Die *cast_type =
          resolve_type_name(fields[i].substr(cast_prefix.size()));
      if (cast_type == NULL) {
        return false;
      }
      *typedie = *cast_type;
      field.pointer = true;
      ++i;
      continue;
    }

    switch (dwarf_tag(typedie)) {
      case DW_TAG_typedef:
      case DW_TAG_const_type:
      case DW_TAG_volatile_type:
      case DW_TAG_restrict_type:
        /* Just iterate on the referent type.  */
        dwarf_die_type(typedie, typedie);
        break;

      case DW_TAG_reference_type:
      case DW_TAG_rvalue_reference_type:
        field.pointer = true;
        dwarf_die_type(typedie, typedie);
        break;
      case DW_TAG_pointer_type:
        /* A pointer with no type is a void* -- can't dereference it. */
        if (!dwarf_hasattr_integrate(typedie, DW_AT_type)) {
          clog << "invalid access pointer " << fields[i] << endl;
          return false;
        }
        field.pointer = true;
        dwarf_die_type(typedie, typedie);
        break;
      case DW_TAG_array_type:
        // TODO: array element access is not resolved yet
        clog << "unsupported array access " << fields[i] << endl;
        return false;
      case DW_TAG_structure_type:
      case DW_TAG_union_type:
      case DW_TAG_class_type: {
        if (dwarf_hasattr(typedie, DW_AT_declaration)) {
          Dwarf_Die *tmpdie = resolve_typedecl(typedie);
          if (tmpdie == NULL) {
            clog << "couldn't resolve type at " << fields[i] << endl;
            return false;
          }

          *typedie = *tmpdie;
        }
        Dwarf_Attribute attr;
        if (!find_class_member(vardie, typedie, fields[i], &attr)) {
          clog << "failed to find member location for " << fields[i] << endl;
          return false;
        }
        Dwarf_Op *expr;
        size_t len;
        if (dwarf_getlocation_addr(&attr, pc, &expr, &len, 1) != 1 || len == 0) {
          clog << "failed to get location of attr for " << fields[i] << endl;
          return false;
        }
        VarLocation varloc;
        if (!translate_expr(NULL, expr, pc, varloc)) {
          clog << "failed to translate location of " << fields[i] << endl;
          return false;
        }
        field.offset = varloc.offset;
        res.push_back(field);
        field = {0, false};

        dwarf_die_type(vardie, typedie);
        ++i;
      } break;
      case DW_TAG_enumeration_type:
      case DW_TAG_base_type:
        clog << "invalid access enum or base type " << fields[i] << endl;
        return false;
      default:
        clog << "unexpected type " << fields[i] << endl;
        return false;
    }
  }
  return true;
}

bool DwarfParser::filter_func(string funcname) {
  for (auto x : probes) {
    size_t found = x.first.find_last_of(":");
    string name = x.first.substr(found + 1);
    if (funcname == name) return true;
  }
  return false;
}

bool DwarfParser::filter_cu(string unitname) {
  size_t found = unitname.find_last_of("/");
  string name = unitname.substr(found + 1);

  for (auto x : probe_units) {
    if (x == name) return true;
  }
  return false;
}

std::string special_inlined_function_scope(const char *funcname){
  if (strcmp(funcname, "log_latency") == 0)
    return "BlueStore";
  if (strcmp(funcname, "log_latency_fn") == 0)
    return "BlueStore";
  return "";
}

// implement the callback function handle_attr
static int handle_attr(Dwarf_Attribute *attr, void *data) {
  (void)data;
  unsigned int code = dwarf_whatattr(attr);
  unsigned int form = dwarf_whatform(attr);
  // print code name and form name
  printf("  code: %s, form: %s\n", DwarfParser::dwarf_attr_string(code), DwarfParser::dwarf_form_string(form));
  return 0;
}

static int handle_function(Dwarf_Die *die, void *data) {
  assert(data != NULL);
  DwarfParser *dp = (DwarfParser *)data;
  const char *funcname = dwarf_diename(die);
  if (!dp->filter_func(funcname)) return 0;
  Dwarf_Die func_abstract = *die;
  // in case of compiler's lto optimization, need to find the abstract function die 
  // in the source code module
  if (dwarf_hasattr(die, DW_AT_abstract_origin)) {
    Dwarf_Attribute attr_mem;
    Dwarf_Attribute *tmpattr =
        dwarf_attr_integrate(die, DW_AT_abstract_origin, &attr_mem);
    dwarf_formref_die(tmpattr, &func_abstract);
  }

  Dwarf_Die func_spec = func_abstract;
  if (dwarf_hasattr(&func_abstract, DW_AT_specification)) {
    Dwarf_Attribute attr_mem;
    Dwarf_Attribute *tmpattr =
        dwarf_attr_integrate(&func_abstract, DW_AT_specification, &attr_mem);
    dwarf_formref_die(tmpattr, &func_spec);
  }
  Dwarf_Die *scopes;
  int nscopes = dwarf_getscopes_die(&func_spec, &scopes);
  
  string fullname = funcname;

  if (nscopes > 1) {
    string scopename = special_inlined_function_scope(funcname);
    if (dwarf_tag(&scopes[1]) == DW_TAG_class_type || 
                    dwarf_tag(&scopes[1]) == DW_TAG_structure_type) {
      scopename = dwarf_diename(&scopes[1]);
    }
    if (!scopename.empty()) {
      fullname = scopename + "::" + fullname;
    
    }
  }

  // debug: printf("function fullname is %s\n", fullname.c_str());
  if (dp->probes.find(fullname) == dp->probes.end()) {
    return 0;
  }

  //TODO Need to find all the instances of the inlined function, now we just filter those inline function
  if (dwarf_func_inline(die) != 0) {
     // Refer to elfutils/tests: we can iterate all inlined instances via below function
     // dwarf_func_inline_instances(die, &handle_instance, NULL);
     return 0;
  } 
  
  if (dwarf_getattrs(die, handle_attr, NULL, 0) != 1) {
    cerr << "dwarf_getattrs failed" << endl;
  }

  // TODO need to check if the class name matches
  Dwarf_Addr pc;
  if (!dp->find_prologue(die, pc)) {
    // LTO optimization will not generate the low_pc/high_pc/rangs for the abstract function
    return 0;
  }
  auto &func2pc = dp->mod_func2pc[dp->cur_mod_name];
  func2pc[fullname] = pc;

  auto &func2vf = dp->mod_func2vf[dp->cur_mod_name];
  auto &vf = func2vf[fullname];
  auto arr = dp->probes[fullname];
  vf.resize(arr.size());

  for (int i = 0; i < (int)arr.size(); ++i) {
    string varname = arr[i][0];
    Dwarf_Die vardie, typedie;
    VarLocation varloc;
    bool ok = dp->translate_param_location(die, varname, pc, vardie, varloc);
    assert(ok);
    //printf("var %s location : register %d, offset %d, stack %d\n",
     //varname.c_str(), varloc.reg, varloc.offset, varloc.stack);
    vf[i].varloc = varloc;

    // translate fileds
    dp->dwarf_die_type(&vardie, &typedie);
    ok = dp->translate_fields(&vardie, &typedie, pc, arr[i], vf[i].fields);
    assert(ok);
    for (int j = 1; j < (int)vf[i].fields.size(); ++j) {
       //printf("Field %s is at offset %d, defref %d\n", arr[i][j].c_str(),
       //vf[i].fields[j].offset, vf[i].fields[j].pointer);
    }
  }
  return 0;
}

bool DwarfParser::translate_expr(Dwarf_Attribute *fb_attr, Dwarf_Op *expr,
                                 Dwarf_Addr pc, VarLocation &varloc) {
  assert(expr != NULL);
  int atom = expr->atom;

  // TODO can put a debug message to print the atom's name in string

  switch (atom) {
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
      clog << "atom " << atom << endl;
      break;

    case DW_OP_bregx:
      varloc.reg = expr->number;
      varloc.offset = expr->number2;
      break;

    case DW_OP_breg0 ... DW_OP_breg31:
      varloc.reg = expr->atom - DW_OP_breg0;
      varloc.offset = expr->number;
      break;

    case DW_OP_fbreg: {
      if (fb_attr == NULL) {
        cerr << "translate_expr: DW_OP_fbreg with no frame base" << endl;
        return false;
      }
      Dwarf_Op *fb_expr;
      size_t fb_exprlen;
      int res = dwarf_getlocation_addr(fb_attr, pc, &fb_expr, &fb_exprlen, 1);
      if (res != 1 || fb_exprlen == 0) {
        cerr << "translate_expr get fb_expr failed" << endl;
        return false;
      }

      if (!translate_expr(fb_attr, fb_expr, pc, varloc)) return false;
      varloc.offset += expr->number;
      varloc.stack = true;
    } break;

    case DW_OP_call_frame_cfa: {
      Dwarf_Op *cfa_ops = NULL;
      size_t cfa_nops = 0;
      // Try .debug_frame first
      Dwarf_Frame *frame = NULL;
      if (cfi_debug != NULL) {
        if (dwarf_cfi_addrframe(cfi_debug, pc, &frame) == 0) {
          dwarf_frame_cfa(frame, &cfa_ops, &cfa_nops);
        } else {
          cerr << "dwarf_frame_cfa add debug frame failed" << endl;
        }
      }

      if (cfa_ops == NULL && cfi_eh != NULL) {
        if (dwarf_cfi_addrframe(cfi_eh, pc, &frame) == 0) {
          dwarf_frame_cfa(frame, &cfa_ops, &cfa_nops);
        } else {
          cerr << "dwarf_frame_cfa add eh frame failed" << endl;
        }
      }

      if (cfa_ops == NULL) {
        cerr << "translate_expr: could not resolve call frame CFA" << endl;
        return false;
      }

      return translate_expr(fb_attr, cfa_ops, pc, varloc);
    }
    case DW_OP_reg0 ... DW_OP_reg31:
      varloc.reg = expr->atom - DW_OP_reg0;
      break;

    case DW_OP_plus_uconst:
      varloc.offset = expr->number;
      break;

    default:
      break;
  }
  return true;
}

Dwfl *DwarfParser::create_dwfl(int fd, const char *fname) {
  int dwfl_fd = dup(fd);
  Dwfl *dwfl = NULL;
  if (dwfl_fd < 0) {
    cerr << "create_dwfl dup failed" << endl;
    return 0;
  }

  static const Dwfl_Callbacks callbacks = {
      .find_elf = dwfl_linux_proc_find_elf,
      .find_debuginfo = dwfl_standard_find_debuginfo,
      .section_address = dwfl_offline_section_address,
      .debuginfo_path = nullptr};

  dwfl = dwfl_begin(&callbacks);

  // if(dwfl != NULL)
  // dwfl->offline_next_address = 0;

  if (dwfl_report_offline(dwfl, fname, fname, dwfl_fd) == NULL) {
    cerr << "dwfl_report_offline open dwfl failed" << endl;
    close(dwfl_fd);
    dwfl = NULL;
  } else
    dwfl_report_end(dwfl, NULL, NULL);

  return dwfl;
}


static int preprocess_module(Dwfl_Module *dwflmod, void **userdata,
                         const char *name, Dwarf_Addr base, void *arg) {
  (void)userdata;
  (void)name;
  (void)base;

  DwarfParser *dp = (DwarfParser *)arg;
  assert(dwflmod != NULL && dp != NULL);

  dp->cur_mod = dwflmod;
  const char* mod_path = dwfl_module_info(dwflmod, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
  dp->cur_mod_name = get_basename(mod_path);
  Dwarf_Addr modbias;
  Dwarf *dwarf = dwfl_module_getdwarf(dwflmod, &modbias);

  if (!dwarf) {
    cerr << "preprocess_module dwarf get error" << endl;
    clog << "Please ensure the debug symbol is installed" << endl;
    return EXIT_FAILURE;
  }


  dp->traverse_module(dwflmod, dwarf, true); 
  for (const auto& type_name : dp->requested_type_sizes) {
    int size = dp->resolve_type_size(dwflmod, type_name);
    if (size > 0)
      dp->mod_type_sizes[dp->cur_mod_name][type_name] = size;
  }
  return 0;
}


static int handle_module(Dwfl_Module *dwflmod, void **userdata,
                         const char *name, Dwarf_Addr base, void *arg) {
  (void)userdata;
  (void)name;
  (void)base;

  DwarfParser *dp = (DwarfParser *)arg;
  assert(dwflmod != NULL && dp != NULL);

  dp->cur_mod = dwflmod;
  const char* mod_path = dwfl_module_info(dwflmod, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
  dp->cur_mod_name = get_basename(mod_path);
  Dwarf_Addr modbias;
  Dwarf *dwarf = dwfl_module_getdwarf(dwflmod, &modbias);

  if (!dwarf) {
    cerr << "handle_module dwarf get error" << endl;
    return EXIT_FAILURE;
  }

  int start_time = clock();

  Dwarf_Off offset = 0;
  Dwarf_Off next_offset;
  size_t header_size;
  Dwarf_Die cu_die;

  while (dwarf_nextcu(dwarf, offset, &next_offset, &header_size, nullptr,
                      nullptr, nullptr) == 0) {
    if (dwarf_offdie(dwarf, offset + header_size, &cu_die) != nullptr) {
      dp->cfi_debug = dwfl_module_dwarf_cfi(dwflmod, &dp->cfi_debug_bias);
      dp->cfi_eh = dwfl_module_eh_cfi(dwflmod, &dp->cfi_eh_bias);
      assert(dp->cfi_debug == NULL || dp->cfi_debug_bias == 0);

      string cu_name = dwarf_diename(&cu_die) ?: "<unknown>";
      //cout << "handle_module cu name " << cu_name << endl;
      if (dp->filter_cu(cu_name) || cu_name == "<artificial>") {
        //cout << "cu name " << cu_name << endl;
        dp->cur_cu = &cu_die;
        dwarf_getfuncs(&cu_die, (int (*)(Dwarf_Die *, void *))handle_function,
                       dp, 0);
      }
    }
    offset = next_offset;
  }
  int end_process_funcs_time = clock();

  clog << "process functions take "
       << (end_process_funcs_time - start_time) / double(CLOCKS_PER_SEC) * 1000
       << endl;
  return 0;
}

int DwarfParser::parse() {
  if(getenv("DEBUGINFOD_URLS") == NULL) {
    //If the DEBUGINFOD_URLS is not set, set it to https://debuginfod.ubuntu.com as default
    setenv("DEBUGINFOD_URLS", "https://debuginfod.ubuntu.com", 0);
  }

  for (auto dwfl: dwfls) {
    dwfl_getmodules(dwfl, preprocess_module, this, 0);
  }
  for (auto dwfl: dwfls) {
    dwfl_getmodules(dwfl, handle_module, this, 0);
  }
  return 0;
}

void DwarfParser::add_module(string path) {
  const char *fname = path.c_str();
  int fd = open(fname, O_RDONLY);
  if (fd == -1) {
    cerr << "cannot open input file " << fname;
  }

  // Remember the full path keyed by basename so export_to_json() can locate
  // the on-disk ELF later for build-id extraction without re-resolving it.
  mod_path[get_basename(path)] = path;

  Dwfl *dwfl = create_dwfl(fd, fname);
  dwfls.push_back(dwfl);
}

DwarfParser::DwarfParser(probes_t ps, vector<string> pus)
    : probe_units(pus),
      probes(ps),
      cur_mod(NULL),
      cur_cu(NULL),
      cfi_debug(NULL),
      cfi_eh(NULL) {
}

DwarfParser::~DwarfParser() {}

void DwarfParser::export_to_json(const std::string& filename, const std::string& version) {
    json j;

    // Add version information first if provided (will appear at the top)
    if (!version.empty()) {
        j["version"] = version;
    }

    // Record the host architecture so the consumer can refuse the JSON on a
    // mismatched target (build-id keying is per-arch by construction, but
    // tooling that looks at the file as data still benefits from the field).
    std::string arch = get_host_arch();
    if (!arch.empty()) {
        j["arch"] = arch;
    }

    std::set<std::string> modules;
    for (const auto& [module, unused] : mod_func2pc) {
        (void)unused;
        modules.insert(module);
    }
    for (const auto& [module, unused] : mod_func2vf) {
        (void)unused;
        modules.insert(module);
    }
    for (const auto& [module, unused] : mod_type_sizes) {
        (void)unused;
        modules.insert(module);
    }

    for (const auto& module : modules) {
        json module_obj;

        // Read the on-disk ELF build-id for this module.  mod_path is
        // populated by add_module(); empty if the JSON was loaded from a
        // file (export-then-export round-trip), in which case we cannot
        // compute a build-id and the field is omitted.
        auto path_it = mod_path.find(module);
        if (path_it != mod_path.end()) {
            std::string bid = get_elf_build_id(path_it->second);
            if (!bid.empty()) {
                module_obj["build_id"] = bid;
            }
        }

        // Add function addresses (mod_func2pc)
        json pc_obj = json::object();
        if (mod_func2pc.count(module) > 0) {
            for (const auto& func_pc : mod_func2pc[module]) {
                pc_obj[func_pc.first] = func_pc.second;
            }
        }
        module_obj["func2pc"] = pc_obj;

        json type_sizes_obj = json::object();
        auto sizes_it = mod_type_sizes.find(module);
        if (sizes_it != mod_type_sizes.end()) {
            for (const auto& [type_name, size] : sizes_it->second) {
                type_sizes_obj[type_name] = size;
            }
        }
        module_obj["type_sizes"] = type_sizes_obj;

        // Add function variable fields (mod_func2vf)
        json vf_obj = json::object();
        for (const auto& func_pair : mod_func2vf[module]) {
            const std::string& function = func_pair.first;
            json func_obj;

            // Convert vector of VarFields to JSON array
            json vars_array = json::array();
            for (const auto& var_field : func_pair.second) {
                json var_obj;
                
                // Store VarLocation
                var_obj["location"] = {
                    {"reg", var_field.varloc.reg},
                    {"offset", var_field.varloc.offset},
                    {"stack", var_field.varloc.stack}
                };

                // Store Fields
                json fields_array = json::array();
                for (const auto& field : var_field.fields) {
                    fields_array.push_back({
                        {"offset", field.offset},
                        {"pointer", field.pointer}
                    });
                }
                var_obj["fields"] = fields_array;

                vars_array.push_back(var_obj);
            }
            func_obj["var_fields"] = vars_array;
            vf_obj[function] = func_obj;
        }
        module_obj["func2vf"] = vf_obj;

        j[module] = module_obj;
    }

    // Write to file
    std::ofstream out(filename);
    if (!out.is_open()) {
        std::cerr << "Failed to open output file: " << filename << std::endl;
        return;
    }
    out << j.dump(2);  // The '2' parameter adds indentation for pretty printing
    out.close();
}

bool DwarfParser::import_from_json(const std::string& filename, const std::string& expected_version) {
    try {
        // Read JSON file
        std::ifstream input(filename);
        if (!input.is_open()) {
            std::cerr << "Failed to open input file: " << filename << std::endl;
            return false;
        }
        
        json j;
        input >> j;
        input.close();

        // Check version compatibility if expected_version is provided
        if (!expected_version.empty()) {
            if (j.contains("version")) {
                std::string json_version = j["version"].get<std::string>();
                if (json_version != expected_version) {
                    std::cerr << "Version mismatch! JSON file version: " << json_version 
                              << ", Expected version: " << expected_version << std::endl;
                    std::cerr << "The JSON file was generated for a different version of the library." << std::endl;
                    std::cerr << "Please regenerate the JSON file or use the correct library version." << std::endl;
                    return false;
                }
                std::cout << "Version check passed: " << json_version << std::endl;
            } else {
                std::cerr << "Error: JSON file does not contain version information." << std::endl;
                std::cerr << "Expected version: " << expected_version << std::endl;
                return false;
            }
        }

        // Clear existing data
        mod_func2pc.clear();
        mod_func2vf.clear();
        mod_type_sizes.clear();

        // Parse JSON structure
        for (const auto& [module, module_data] : j.items()) {
            // Skip top-level metadata (version, arch, future additions).
            // Only iterate entries that look like module objects, i.e. have
            // func2pc and/or func2vf children.  More robust than a hard-coded
            // skip-list as new metadata fields are added.
            if (!module_data.is_object()) {
                continue;
            }
            if (!module_data.contains("func2pc") && !module_data.contains("func2vf")) {
                continue;
            }

            // Convert absolute path to basename for backward compatibility
            // Legacy JSON files use full paths (e.g., "/usr/bin/ceph-osd")
            // New code expects basenames (e.g., "ceph-osd")
            std::string key = get_basename(module);

            // Import func2pc data
            if (module_data.contains("func2pc")) {
                const auto& pc_obj = module_data["func2pc"];
                for (const auto& [func_name, addr] : pc_obj.items()) {
                    mod_func2pc[key][func_name] = addr.get<Dwarf_Addr>();
                }
            }

            if (module_data.contains("type_sizes")) {
                for (const auto& [type_name, size] :
                     module_data["type_sizes"].items()) {
                    mod_type_sizes[key][type_name] = size.get<uint32_t>();
                }
            }

            // Import func2vf data
            if (module_data.contains("func2vf")) {
                const auto& vf_obj = module_data["func2vf"];
                for (const auto& [func_name, func_data] : vf_obj.items()) {
                    std::vector<VarField> var_fields;
                    
                    for (const auto& var_field_json : func_data["var_fields"]) {
                        VarField var_field;
                        
                        // Parse VarLocation
                        const auto& loc = var_field_json["location"];
                        var_field.varloc.reg = loc["reg"].get<int>();
                        var_field.varloc.offset = loc["offset"].get<int>();
                        var_field.varloc.stack = loc["stack"].get<bool>();

                        // Parse Fields
                        for (const auto& field_json : var_field_json["fields"]) {
                            Field field;
                            field.offset = field_json["offset"].get<int>();
                            field.pointer = field_json["pointer"].get<bool>();
                            var_field.fields.push_back(field);
                        }

                        var_fields.push_back(var_field);
                    }

                    mod_func2vf[key][func_name] = var_fields;
                }
            }
        }

        return true;
    } catch (const json::exception& e) {
        std::cerr << "JSON parsing error: " << e.what() << std::endl;
        return false;
    } catch (const std::exception& e) {
        std::cerr << "Error importing from JSON: " << e.what() << std::endl;
        return false;
    }
}

// Find the embedded entry whose per-module build-ids match the caller's set,
// or nullptr if none.  Shared by import_from_embedded() (which then loads the
// data) and is_embedded_traceable() (which only reports the verdict).
static const EmbeddedVersion* find_embedded_match(
    const std::vector<std::pair<std::string, std::string>>& modules,
    const std::string& trace_type) {
    const EmbeddedVersion* versions = nullptr;
    int count = 0;

    if (trace_type == "osdtrace") {
        versions = EMBEDDED_OSDTRACE_VERSIONS;
        count = EMBEDDED_OSDTRACE_COUNT;
    } else if (trace_type == "radostrace") {
        versions = EMBEDDED_RADOSTRACE_VERSIONS;
        count = EMBEDDED_RADOSTRACE_COUNT;
    } else {
        return nullptr;
    }

    // Build the caller's (basename, build-id) set.  An empty build-id on
    // the caller side means we couldn't read the note from the target
    // binary (snap-mounted readonly squashfs that lacks one, stripped
    // image, etc.) — refuse the lookup in that case so we don't accept a
    // partial match against an embedded entry whose own build-id is also
    // empty (legacy JSON).
    std::set<std::pair<std::string, std::string>> want;
    for (const auto& m : modules) {
        if (m.second.empty()) {
            return nullptr;
        }
        want.emplace(m.first, m.second);
    }
    if (want.empty()) {
        return nullptr;
    }

    // Linear scan: an entry matches iff every module the caller asked for
    // (`want`) is present in the entry with the same build-id, i.e. want is a
    // subset of the entry's modules.  Callers pass a single identifying
    // library — libceph-common.so.2 for radostrace, ceph-osd for osdtrace —
    // whose build-id pins the exact package build; an entry may carry extra
    // modules (e.g. pre-20.2 radostrace entries also hold librbd/librados,
    // which import_from_embedded loads too) that the caller need not name.
    // The per-module build-id pins identity, so this can't confuse two
    // different package versions.  Any empty build-id in the embedded data is
    // skipped, so legacy JSONs predating the build-id scheme never match.
    for (int i = 0; i < count; ++i) {
        const EmbeddedVersion& v = versions[i];
        if (v.num_modules == 0) continue;

        std::set<std::pair<std::string, std::string>> have;
        for (int m = 0; m < v.num_modules; ++m) {
            const char* bid = v.modules[m].build_id;
            if (bid && *bid != '\0') have.emplace(v.modules[m].module_name, bid);
        }

        bool all_match = true;
        for (const auto& w : want) {
            if (have.find(w) == have.end()) { all_match = false; break; }
        }
        if (all_match) {
            return &v;
        }
    }

    return nullptr;
}

bool DwarfParser::import_from_embedded(
    const std::vector<std::pair<std::string, std::string>>& modules,
    const std::string& trace_type,
    std::string* matched_version_out) {
    const EmbeddedVersion* match = find_embedded_match(modules, trace_type);
    if (!match) {
        return false;
    }

    // Marker line preserves the "Using embedded DWARF data" prefix that
    // tests (and downstream log consumers) grep for; the detailed
    // per-module build-ids follow so a failing trace can be correlated
    // with the exact embedded entry that was used.
    std::clog << "Using embedded DWARF data (version "
              << (match->version ? match->version : "?")
              << ", arch " << (match->arch && *match->arch ? match->arch : "unspecified")
              << "):" << std::endl;
    for (int m = 0; m < match->num_modules; ++m) {
        std::clog << "  " << match->modules[m].module_name
                  << " build-id " << match->modules[m].build_id << std::endl;
    }

    // Clear existing data
    mod_func2pc.clear();
    mod_func2vf.clear();
    mod_type_sizes.clear();

    // Populate from embedded data
    for (int m = 0; m < match->num_modules; ++m) {
        const auto& mod = match->modules[m];
        std::string mod_name(mod.module_name);

        for (int t = 0; t < mod.num_type_sizes; ++t) {
            mod_type_sizes[mod_name][mod.type_sizes[t].type_name] =
                mod.type_sizes[t].size;
        }

        // Import func2pc
        for (int f = 0; f < mod.num_func2pc; ++f) {
            mod_func2pc[mod_name][mod.func2pc[f].func_name] = mod.func2pc[f].addr;
        }

        // Import func2vf
        for (int f = 0; f < mod.num_func2vf; ++f) {
            const auto& fvf = mod.func2vf[f];
            std::vector<VarField> var_fields;

            for (int v = 0; v < fvf.num_var_fields; ++v) {
                VarField vf;
                vf.varloc.reg = fvf.var_fields[v].location.reg;
                vf.varloc.offset = fvf.var_fields[v].location.offset;
                vf.varloc.stack = fvf.var_fields[v].location.stack;

                for (int fi = 0; fi < fvf.var_fields[v].num_fields; ++fi) {
                    Field field;
                    field.offset = fvf.var_fields[v].fields[fi].offset;
                    field.pointer = fvf.var_fields[v].fields[fi].pointer;
                    vf.fields.push_back(field);
                }

                var_fields.push_back(vf);
            }

            mod_func2vf[mod_name][fvf.func_name] = var_fields;
        }
    }

    if (matched_version_out && match->version) {
        *matched_version_out = match->version;
    }

    return true;
}

void DwarfParser::list_embedded_versions(const std::string& trace_type) {
    const EmbeddedVersion* versions = nullptr;
    int count = 0;

    if (trace_type == "osdtrace") {
        versions = EMBEDDED_OSDTRACE_VERSIONS;
        count = EMBEDDED_OSDTRACE_COUNT;
    } else if (trace_type == "radostrace") {
        versions = EMBEDDED_RADOSTRACE_VERSIONS;
        count = EMBEDDED_RADOSTRACE_COUNT;
    } else {
        std::cerr << "Unknown trace type: " << trace_type << std::endl;
        return;
    }

    std::cout << count << " Ceph version(s) with embedded " << trace_type
              << " DWARF data:" << std::endl;
    printf("  %-32s %-8s %-22s %s\n", "VERSION", "ARCH", "MODULE", "BUILD ID");
    printf("  %-32s %-8s %-22s %s\n",
                "--------------------------------", "--------",
                "----------------------", "----------------------------------------");
    for (int i = 0; i < count; ++i) {
        const EmbeddedVersion& v = versions[i];
        const char* ver = (v.version && *v.version) ? v.version : "(unknown)";
        const char* arch = (v.arch && *v.arch) ? v.arch : "-";
        if (v.num_modules == 0) {
            printf("  %-32s %-8s %-22s %s\n", ver, arch, "-", "-");
            continue;
        }
        // One row per module; repeat version/arch only on the first row so a
        // multi-module entry (radostrace) reads as a single grouped record.
        for (int m = 0; m < v.num_modules; ++m) {
            const char* mod = v.modules[m].module_name ? v.modules[m].module_name : "-";
            const char* bid = (v.modules[m].build_id && *v.modules[m].build_id)
                                  ? v.modules[m].build_id : "(none)";
            printf("  %-32s %-8s %-22s %s\n",
                        m == 0 ? ver : "", m == 0 ? arch : "", mod, bid);
        }
    }
}

bool DwarfParser::is_embedded_traceable(
    const std::vector<std::pair<std::string, std::string>>& modules,
    const std::string& trace_type,
    std::string* matched_version_out) {
    const EmbeddedVersion* match = find_embedded_match(modules, trace_type);
    if (!match) {
        return false;
    }
    if (matched_version_out && match->version) {
        *matched_version_out = match->version;
    }
    return true;
}

const char* DwarfParser::dwarf_attr_string(unsigned int attrnum) {
  switch (attrnum) {
    #define DWARF_ONE_KNOWN_DW_AT(NAME, CODE) case CODE: return  "DW_AT_"#NAME;
    DWARF_ALL_KNOWN_DW_AT
    #undef DWARF_ONE_KNOWN_DW_AT
    default:
      return "DW_AT_<unknown>";
  }
}

const char* DwarfParser::dwarf_form_string(unsigned int form) {
  switch (form) {
    #define DWARF_ONE_KNOWN_DW_FORM(NAME, CODE) case CODE: return "DW_FORM_"#NAME;
    DWARF_ALL_KNOWN_DW_FORM
    #undef DWARF_ONE_KNOWN_DW_FORM
    default:
      return "DW_FORM_<unknown>";
  }
}
