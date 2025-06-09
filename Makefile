CLANG := clang
CXX := g++
OUTPUT := .output
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')

# Source paths
OSDTRACE_SRC := $(abspath ./src)

# Check for required tools and libraries
BPFTOOL := $(shell which bpftool 2>/dev/null)
ifeq ($(BPFTOOL),)
    $(error "bpftool not found. Please install bpftool package")
endif

# Find libbpf headers
LIBBPF_HEADER_PATH := $(shell find /usr/include /usr/local/include -name libbpf.h -type f 2>/dev/null | head -n1 | xargs dirname)
ifeq ($(LIBBPF_HEADER_PATH),)
    $(error "libbpf headers not found. Please install libbpf development package")
endif

# Common objects and includes
COMMON_OBJS := $(OUTPUT)/dwarf_parser.o
PROG_OBJS := osdtrace radostrace
PROG_SRCS := $(addprefix $(OSDTRACE_SRC)/,$(addsuffix .cc,$(PROG_OBJS)))
PROG_BPF_SRCS := $(addprefix $(OSDTRACE_SRC)/,$(addsuffix .bpf.c,$(PROG_OBJS)))

# Include paths
INCLUDES := -I$(OUTPUT) \
           -I$(LIBBPF_HEADER_PATH) \
           -I$(abspath ./external/json/include)

# Compiler flags
CLANG_BPF_SYS_INCLUDES := $(shell $(CLANG) -v -E - </dev/null 2>&1 | \
    sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')
CXXFLAGS := -g -O2 -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES)
LIBS := -lbpf -lelf -ldw -lz

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

$(OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

# Build BPF objects and skeletons
$(OUTPUT)/%.bpf.o: $(OSDTRACE_SRC)/%.bpf.c | $(OUTPUT)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf $(CXXFLAGS) -c $< -o $(patsubst %.bpf.o,%.tmp.bpf.o,$@)
	$(Q)$(BPFTOOL) gen object $@ $(patsubst %.bpf.o,%.tmp.bpf.o,$@)

$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

# Build object files
$(OUTPUT)/%.o: $(OSDTRACE_SRC)/%.cc $(OSDTRACE_SRC)/*.h $(OUTPUT)/%.skel.h | $(OUTPUT)
	$(call msg,CXX,$@)
	$(Q)$(CXX) $(CXXFLAGS) -c -o $@ $<

# Special rule for dwarf_parser.o since it doesn't need a skel.h
$(OUTPUT)/dwarf_parser.o: $(OSDTRACE_SRC)/dwarf_parser.cc $(OSDTRACE_SRC)/*.h | $(OUTPUT)
	$(call msg,CXX,$@)
	$(Q)$(CXX) $(CXXFLAGS) -c -o $@ $<

# Build final executables
define build_rule
$(1): $(OUTPUT)/$(1).o $(COMMON_OBJS) $(OUTPUT)/$(1).skel.h | $(OUTPUT)
	$$(call msg,LINK,$$@)
	$(Q)$$(CXX) $$(CXXFLAGS) -o $$@ $$< $$(COMMON_OBJS) $$(LIBS)
endef

$(foreach prog,$(PROG_OBJS),$(eval $(call build_rule,$(prog))))


