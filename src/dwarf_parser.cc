#include "dwarf_parser.h"

bool DwarfParser::die_has_loclist(Dwarf_die *begin_die)
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


bool DwarfParser::has_loclist()
{
    assert(cur_cu);
    return die_has_loclist(cur_cu);
}

Dwarf_Addr DwarfParser::find_prologue(Dwarf_Die *func)
{
  Dwarf_Addr entrypc;
  if (func_entrypc (func, &entrypc) == false)
    printf("error in func_entrypc: %s: %s",
           dwarf_diename (func), dwarf_errmsg (-1));

  int dwbias = 0;
  entrypc += dwbias;

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


bool DwarfParser::func_entrypc(Dwarf_Die *func, Dwarf_Addr *addr)
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


Dwarf_Die * DwarfParser::resolve_typedecl(Dwarf_Die *type) 
{

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


const char* DwarfParser::cache_type_prefix(Dwarf_Die* type)
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


int DwarfParser::iterate_types_in_cu(Dwarf_Die *cu_die)
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

void DwarfParser::traverse_module(
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

Dwarf_Die DwarfParser::find_param(Dwarf_Die *func, std::string symbol)
{
    Dwarf_Die vardie;

    dwarf_getscopevar (func, 1, symbol.c_str(), 0, NULL, 0, 0, &vardie);

    return vardie;
}


Dwarf_Attribute * DwarfParser::find_func_frame_base(Dwarf_Die *func, Dwarf_Attribute *fb_attr_mem)
{
    assert(dwarf_tag(func) == DW_TAG_subprogram);

    Dwarf_Attribute *fb_attr = NULL;
    fb_attr = dwarf_attr_integrate(func, DW_AT_frame_base, fb_attr_mem);
    return fb_attr;
}

VarLocation DwarfParser::translate_param_location(Dwarf_Die *func, std::string symbol, Dwarf_Addr pc, Dwarf_Die &vardie)
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


VarLocation DwarfParser::translate_param_location(Dwarf_Die *func, std::string symbol, Dwarf_Addr pc, Dwarf_Die &vardie)
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

Dwarf_Addr DwarfParser::find_prologue(Dwarf_Die *func)
{
  Dwarf_Addr entrypc;
  if (func_entrypc (func, &entrypc) == false)
    printf("error in func_entrypc: %s: %s",
           dwarf_diename (func), dwarf_errmsg (-1));

  int dwbias = 0;
  entrypc += dwbias;

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


void DwarfParser::dwarf_die_type (Dwarf_Die *die, Dwarf_Die *typedie_mem)
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

void DwarfParser::find_class_member(Dwarf_Die *vardie, Dwarf_Die *typedie,
		       std::string member, Dwarf_Attribute *attr)
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

void DwarfParser::translate_fields(Dwarf_Die *vardie,
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

bool DwarfParser::filter_func(std::string funcname)
{
    for(auto x : probes) {
	std::size_t found = x.first.find_last_of(":");
	std::string name = x.first.substr(found+1);
	if(funcname == name) 
	    return true;
    }
    return false;
}

bool DwarfParser::filter_cu(std::string unitname)
{
    std::size_t found = unitname.find_last_of("/");
    std::string name = unitname.substr(found+1);
    
    for(auto x : probe_units) {
	if(x == name) 
	    return true;
    }
    return false;
}

int DwarfParser::handle_function(Dwarf_Die *die, void *data)
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


void DwarfParser::translate_expr(Dwarf_Attribute *fb_attr, Dwarf_Op *expr, Dwarf_Addr pc, VarLocation &varloc)
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

Dwfl* DwarfParser::create_dwfl (int fd, const char *fname)
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

int DwarfParser::handle_module (Dwfl_Module *dwflmod, void **userdata,
	                        const char *name, Dwarf_Addr base,
	                        void *arg)
{
    assert(dwflmod != NULL);
    cur_mod = dwflmod;
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

int DwarfParser::parse_dwarf();
{
    bool seen = false; 
    dwfl_getmodules(dwfl, handle_module, &seen, 0);
    return 0;
}

void DwarfParser::print_die(Dwarf_Die *die) {
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

DwarfParser::DwarfParser( std::string path,
	                  probes_t ps,
			  std::vector<std::string> pus) :
    cur_mod(NULL),
    cur_cu(NULL),
    cfi_debug(NULL),
    cfi_eh(NULL),
    probes(ps),
    probe_units(pus);
{
    const char *fname = path.c_str();
    int fd = open(fname, O_RDONLY);
    if (fd == -1)
    {
	printf("cannot open input file '%s'", fname);
	return 0;
    }
    
    dwfl = create_dwfl (fd, fname);
}

DwarfParser::~DwarfParser()
{

}


