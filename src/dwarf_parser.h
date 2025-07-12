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
  void print_die(Dwarf_Die *);
  bool die_has_loclist(Dwarf_Die *);
  bool has_loclist();
  Dwarf_Die *resolve_typedecl(Dwarf_Die *);
  const char *cache_type_prefix(Dwarf_Die *);
  int iterate_types_in_cu(mod_cu_type_cache_t &, Dwarf_Die *);
  void traverse_module(Dwfl_Module *, Dwarf *, bool);
  Dwarf_Die find_param(Dwarf_Die *, std::string);
  Dwarf_Attribute *find_func_frame_base(Dwarf_Die *, Dwarf_Attribute *);
  VarLocation translate_param_location(Dwarf_Die *, std::string, Dwarf_Addr,
                                       Dwarf_Die &);
  bool func_entrypc(Dwarf_Die *, Dwarf_Addr *);
  bool find_prologue(Dwarf_Die *func, Dwarf_Addr &pc);
  void dwarf_die_type(Dwarf_Die *, Dwarf_Die *);
  void find_class_member(Dwarf_Die *, Dwarf_Die *, std::string,
                         Dwarf_Attribute *);
  void translate_fields(Dwarf_Die *, Dwarf_Die *, Dwarf_Addr,
                        std::vector<std::string>, std::vector<Field> &);
  bool filter_func(std::string);
  bool filter_cu(std::string);
  void translate_expr(Dwarf_Attribute *, Dwarf_Op *, Dwarf_Addr, VarLocation &);
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

  static const char* dwarf_attr_string(unsigned int attrnum);
  static const char* dwarf_form_string(unsigned int form);
};

#endif
