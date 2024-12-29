CLANG := clang
CXX := g++
OUTPUT := .output
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')

# Source and tool paths
OSDTRACE_SRC := $(abspath ./src)
BPFTOOL_OUTPUT := $(abspath $(OUTPUT)/bpftool)
BPFTOOL := $(BPFTOOL_OUTPUT)/bootstrap/bpftool
BPFTOOL_SRC := $(abspath ./bpftool/src)
LIBBPF_TOP := $(abspath ./libbpf)
LIBBPF_SRC := $(LIBBPF_TOP)/src
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)

# Common objects and includes
COMMON_OBJS := $(OUTPUT)/dwarf_parser.o
PROG_OBJS := osdtrace radostrace
PROG_SRCS := $(addprefix $(OSDTRACE_SRC)/,$(addsuffix .cc,$(PROG_OBJS)))
PROG_BPF_SRCS := $(addprefix $(OSDTRACE_SRC)/,$(addsuffix .bpf.c,$(PROG_OBJS)))

# Include paths
INCLUDES := -I$(OUTPUT) \
           -I$(LIBBPF_TOP)/include/uapi \
           -I$(LIBBPF_SRC) \
           -I$(abspath ./external/json/include)

# Compiler flags
CLANG_BPF_SYS_INCLUDES := $(shell $(CLANG) -v -E - </dev/null 2>&1 | \
    sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')
CXXFLAGS := -g -O2 -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES)
LIBS := $(LIBBPF_OBJ) -lelf -ldw -lz

# Build verbosity control
ifeq ($(V),1)
    Q =
    msg =
else
    Q = @
    msg = @printf '  %-8s %s%s\n' "$(1)" "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))" "$(if $(3), $(3))";
    MAKEFLAGS += --no-print-directory
endif

# Main targets
.PHONY: all clean
all: $(PROG_OBJS)

clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(PROG_OBJS)

$(OUTPUT) $(OUTPUT)/libbpf $(BPFTOOL_OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

# Build rules
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)make -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1 \
	    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@) \
	    INCLUDEDIR= LIBDIR= UAPIDIR= \
	    install

$(BPFTOOL): | $(BPFTOOL_OUTPUT)
	$(call msg,BPFTOOL,$@)
	$(Q)make ARCH= CROSS_COMPILE= OUTPUT=$(BPFTOOL_OUTPUT)/ -C $(BPFTOOL_SRC) bootstrap

# Build BPF objects and skeletons
$(OUTPUT)/%.bpf.o: $(OSDTRACE_SRC)/%.bpf.c $(LIBBPF_OBJ) | $(OUTPUT) $(BPFTOOL)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf $(CXXFLAGS) -c $< -o $(patsubst %.bpf.o,%.tmp.bpf.o,$@)
	$(Q)$(BPFTOOL) gen object $@ $(patsubst %.bpf.o,%.tmp.bpf.o,$@)

$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT) $(BPFTOOL)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

# Build object files
$(OUTPUT)/%.o: $(OSDTRACE_SRC)/%.cc $(OSDTRACE_SRC)/*.h $(OUTPUT)/%.skel.h | $(OUTPUT) $(LIBBPF_OBJ)
	$(call msg,CXX,$@)
	$(Q)$(CXX) $(CXXFLAGS) -c -o $@ $<

# Special rule for dwarf_parser.o since it doesn't need a skel.h
$(OUTPUT)/dwarf_parser.o: $(OSDTRACE_SRC)/dwarf_parser.cc $(OSDTRACE_SRC)/*.h | $(OUTPUT) $(LIBBPF_OBJ)
	$(call msg,CXX,$@)
	$(Q)$(CXX) $(CXXFLAGS) -c -o $@ $<

# Build final executables
define build_rule
$(1): $(OUTPUT)/$(1).o $(COMMON_OBJS) $(OUTPUT)/$(1).skel.h $(LIBBPF_OBJ) | $(OUTPUT)
	$$(call msg,LINK,$$@)
	$(Q)$$(CXX) $$(CXXFLAGS) -o $$@ $$< $$(COMMON_OBJS) $$(LIBS)
endef

$(foreach prog,$(PROG_OBJS),$(eval $(call build_rule,$(prog))))


