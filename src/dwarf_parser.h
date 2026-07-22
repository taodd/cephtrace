#ifndef DWARF_PARSER_H
#define DWARF_PARSER_H

#include <dwarf.h>
#include <elf.h>
#include <elfutils/libdw.h>
#include <elfutils/libdwfl.h>
#include <elfutils/known-dwarf.h>
#include <vector>
#include "nlohmann/json.hpp"  // nlohmann/json library

using json = nlohmann::ordered_json;
class DwarfParser;
static int handle_function(Dwarf_Die *, void *);
static int handle_module(Dwfl_Module *, void **, const char *, Dwarf_Addr,
                         void *);
static int preprocess_module(Dwfl_Module *, void **, const char *, Dwarf_Addr,
                         void *);

class DwarfParser {
 private:
  friend int handle_module(Dwfl_Module *, void **, const char *, Dwarf_Addr,
                           void *);
  friend int handle_function(Dwarf_Die *, void *);
  friend int preprocess_module(Dwfl_Module *, void **, const char *, Dwarf_Addr,
                           void *);

  typedef std::unordered_map<std::string, Dwarf_Die> cu_type_cache_t;
  typedef std::unordered_map<void *, cu_type_cache_t> mod_cu_type_cache_t;
  typedef std::unordered_map<void *, mod_cu_type_cache_t> global_mod_cu_type_cache_t; 
  

  typedef std::map<std::string, std::vector<VarField>> func2vf_t;
  typedef std::map<std::string, Dwarf_Addr> func2pc_t;
  typedef std::map<std::string, func2vf_t> mod_func2vf_t;
  typedef std::map<std::string, func2pc_t> mod_func2pc_t;

 public:
  typedef std::map<std::string, std::vector<std::vector<std::string>>> probes_t;
  mod_func2vf_t mod_func2vf;
  mod_func2pc_t mod_func2pc;
  // basename → full path on disk for every add_module() call.  Lets
  // export_to_json() read each module's ELF build-id without the caller
  // needing to re-derive the path.
  std::map<std::string, std::string> mod_path;
  global_mod_cu_type_cache_t global_type_cache;
  std::vector<std::string> probe_units;
  probes_t probes;

 private:
  std::vector<Dwfl *> dwfls;
  Dwfl_Module *cur_mod;
  std::string cur_mod_name;
  Dwarf_Die *cur_cu;
  Dwarf_CFI *cfi_debug;
  Dwarf_CFI *cfi_eh;
  Dwarf_Addr cfi_debug_bias;
  Dwarf_Addr cfi_eh_bias;

 public:
  int parse();

  DwarfParser(probes_t probes, std::vector<std::string> probe_units);

  ~DwarfParser();
  void add_module(std::string);
  bool die_has_loclist(Dwarf_Die *);
  bool has_loclist();
  Dwarf_Die *resolve_typedecl(Dwarf_Die *);
  Dwarf_Die *resolve_type_name(const std::string&);
  const char *cache_type_prefix(Dwarf_Die *);
  int iterate_types_in_cu(mod_cu_type_cache_t &, Dwarf_Die *);
  void traverse_module(Dwfl_Module *, Dwarf *, bool);
  bool find_param(Dwarf_Die *, std::string, Dwarf_Die &);
  Dwarf_Attribute *find_func_frame_base(Dwarf_Die *, Dwarf_Attribute *);
  bool translate_param_location(Dwarf_Die *, std::string, Dwarf_Addr,
                                Dwarf_Die &, VarLocation &);
  // Recover a parameter's incoming-argument location from the SysV-AMD64
  // calling convention when the DWARF carries no DW_AT_location for it (the
  // compiler can drop the location of a forwarded by-value aggregate under
  // -march=x86-64-v3, e.g. reqid in ReplicatedBackend::submit_transaction).
  // x86-64 builds only: on other architectures it always returns false, so
  // the caller falls back to the normal missing-location failure path.
  bool abi_param_location(Dwarf_Die *func, Dwarf_Die &target, Dwarf_Addr pc,
                          VarLocation &);
  // Resolve the call-frame CFA at pc and add an offset, yielding a stack
  // VarLocation (the same machinery DW_OP_fbreg uses).
  bool abi_stack_location(Dwarf_Die *func, Dwarf_Addr pc, long cfa_off,
                          VarLocation &);
  bool func_entrypc(Dwarf_Die *, Dwarf_Addr *);
  bool find_prologue(Dwarf_Die *func, Dwarf_Addr &pc);
  void dwarf_die_type(Dwarf_Die *, Dwarf_Die *);
  bool find_class_member(Dwarf_Die *, Dwarf_Die *, std::string,
                         Dwarf_Attribute *);
  bool translate_fields(Dwarf_Die *, Dwarf_Die *, Dwarf_Addr,
                        std::vector<std::string>, std::vector<Field> &);
  bool filter_func(std::string);
  bool filter_cu(std::string);
  bool translate_expr(Dwarf_Attribute *, Dwarf_Op *, Dwarf_Addr, VarLocation &);
  Dwfl *create_dwfl(int, const char *);
  std::string special_inlined_function_scope(const char *);
  Dwarf_Die * dwarf_attr_die(Dwarf_Die*, unsigned int, Dwarf_Die*);
  /**
   * Exports the module function data (func2pc and func2vf) to a JSON file
   * @param filename The path to the output JSON file
   * @param version Optional version string to include in the JSON output
   */
  void export_to_json(const std::string& filename, const std::string& version = "");
  /**
   * Imports the module function data (func2pc and func2vf) from a JSON file
   * @param filename The path to the input JSON file
   * @param expected_version Optional expected version string to compare with JSON version
   * @return bool Returns true if import was successful, false otherwise
   */
  bool import_from_json(const std::string& filename, const std::string& expected_version = "");
  /**
   * Imports module function data from compiled-in embedded DWARF data,
   * matching the target binary by ELF GNU build-id.
   *
   * An embedded entry matches iff every (module basename, build-id) pair the
   * caller supplies is present in the entry's `modules[]` — i.e. the caller's
   * set is a subset of the entry's.  The entry may carry extra modules, which
   * import_from_embedded loads as well.  An empty caller-side build-id, or an
   * empty build-id on the embedded module, prevents a match — legacy JSONs
   * without build-id data are therefore never selected by this path.
   *
   * @param modules            Vector of (basename, hex-encoded build-id)
   *                           pairs identifying the target build.  A single
   *                           identifying library suffices since its build-id
   *                           pins the package build.
   *                           For osdtrace: {{"ceph-osd", <hex>}}.
   *                           For radostrace: {{"libceph-common.so.2", <hex>}}.
   * @param trace_type         "osdtrace" or "radostrace".
   * @param matched_version_out If non-null, set to the matched entry's
   *                           version string on success (used by
   *                           radostrace's squid-or-above gate so it can
   *                           avoid a separate dpkg/rpm shell-out).
   * @return true if a matching entry was found and imported.
   */
  bool import_from_embedded(
      const std::vector<std::pair<std::string, std::string>>& modules,
      const std::string& trace_type,
      std::string* matched_version_out = nullptr);

  /**
   * Print the Ceph versions for which DWARF data is compiled into this
   * binary (one row per embedded module, with its build-id), to stdout.
   *
   * @param trace_type "osdtrace" or "radostrace" — selects which embedded
   *                   table to enumerate.
   */
  static void list_embedded_versions(const std::string& trace_type);

  /**
   * Report whether the compiled-in embedded DWARF data covers the given
   * modules, without loading anything (unlike import_from_embedded, this is
   * side-effect free and emits no log output).  Matching is by build-id with
   * the same semantics as import_from_embedded.
   *
   * @param modules            (basename, hex build-id) pairs, as for
   *                           import_from_embedded.
   * @param trace_type         "osdtrace" or "radostrace".
   * @param matched_version_out If non-null, set to the matched version on a
   *                           positive verdict.
   * @return true if the target is traceable with embedded data alone.
   */
  static bool is_embedded_traceable(
      const std::vector<std::pair<std::string, std::string>>& modules,
      const std::string& trace_type,
      std::string* matched_version_out = nullptr);

  static const char* dwarf_attr_string(unsigned int attrnum);
  static const char* dwarf_form_string(unsigned int form);
};

#endif
