#ifndef DWARF_PARSER_H
#define DWARF_PARSER_H



class DwarfParser {

private:
    Dwfl_Module *mod;
    Dwarf_Die *cur_cu;
    Dwarf_CFI * cfi_debug;
    Dwarf_CFI * cfi_eh;
    Dwarf_Addr cfi_debug_bias;
    Dwarf_Addr cfi_eh_bias;

public: 
    int parse_dwarf(std::string path);

private:
    bool die_has_loclist(Dwarf_Die*);
    bool has_loclist();
    Dwarf_Addr find_prologue(Dwarf_Die*);
    bool func_entrypc(Dwarf_Die*, Dwarf_Addr*);
    Dwarf_Die * resolve_typedecl(Dwarf_Die*);
    const char* cache_type_prefix(Dwarf_Di*);
    int iterate_types_in_cu(Dwarf_Die*);
    void traverse_module(Dwfl_Module*, Dwarf*,int (*callback)(Dwarf_Die*), bool);
    Dwarf_Die find_param(Dwarf_Die*, std::string);
    Dwarf_Attribute* find_func_frame_base(Dwarf_Die*, Dwarf_Attribute*);
    VarLocation translate_param_location(Dwarf_Die*, std::string, Dwarf_Addr, Dwarf_Die&);
    bool func_entrypc(Dwarf_Die*, Dwarf_Addr*);
    Dwarf_Addr find_prologue(Dwarf_Die*);
    void dwarf_die_type (Dwarf_Die*, Dwarf_Die*);
    void find_class_member(Dwarf_Die*, Dwarf_Die*, std::string, Dwarf_Attribute);
    void translate_fields(Dwarf_Die*, Dwarf_Die*, Dwarf_Addr,
	                  std::vector<std::string>, std::vector<Field> &);
    bool filter_func(std::string);
    bool filter_cu(std::string);
    int handle_function(Dwarf_Die*,void*);
    void translate_expr(Dwarf_Attribute*, Dwarf_Op*, Dwarf_Addr, VarLocation&);
    Dwfl* create_dwfl (int, const char*);
    int handle_module (Dwfl_Module*, void **, const char*, Dwarf_Addr,void*);

}


#endif
