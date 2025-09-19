VERSION := 1.2
DATE ?= $(shell date +%Y-%m-%d)
SRC_TGT := release
# Populate Source Package Name
ifeq ($(SRC_TGT),debian)
	SRC_PKG := cephtrace_$(VERSION).orig.tar.gz
else
	SRC_PKG := cephtrace-$(VERSION).tar.gz
endif

CLANG := clang
CXX := g++
OUTPUT := .output
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')

# Install location
PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man/man8/
DOCDIR ?= doc/man/8/

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
           -I$(LIBBPF_SRC)

# Compiler flags
CLANG_BPF_SYS_INCLUDES := $(shell $(CLANG) -v -E - </dev/null 2>&1 | \
    sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')
CXXFLAGS := -g -O2 -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES)
LIBS := $(LIBBPF_OBJ) -lelf -ldw -lz -ldl

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

install:
	$(call msg,INSTALL)
	@mkdir -p $(DESTDIR)$(BINDIR)
	@for prog in $(PROG_OBJS); do \
		install -m 0755 $$prog $(DESTDIR)$(BINDIR)/; \
	done
	$(call msg,MAN)
	@mkdir -p $(DESTDIR)$(MANDIR)
	@for prog in $(PROG_OBJS); do \
		sed -e 's/@VERSION@/$(VERSION)/g' \
	    -e 's/@DATE@/$(DATE)/g' $(DOCDIR)/$$prog.rst > $(DOCDIR)/$$prog.rst.in; \
		rst2man $(DOCDIR)/$$prog.rst.in $(DOCDIR)/$$prog.8.gz; \
		install -m 0644 $(DOCDIR)/$$prog.8.gz $(DESTDIR)$(MANDIR)/; \
	done
	
src-pkg:
	$(call msg,BUILD SOURCE PACKAGE)
	TMPDIR=$$(mktemp -d) && \
	cd $$TMPDIR && \
	git clone https://github.com/taodd/cephtrace.git cephtrace-$(VERSION) && \
	cd cephtrace-$(VERSION) && \
	git fetch --all && \
	git checkout main && \
	git pull; git submodule update --init --recursive && \
	cd bpftool; git submodule update --init --recursive && \
	cd $$TMPDIR && \
	tar --exclude cephtrace-$(VERSION)/debian -czf $(SRC_PKG) cephtrace-$(VERSION) && \
	mv $$TMPDIR/$(SRC_PKG) .. -v && \
	cd .. && \
	rm -rf $$TMPDIR/

clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(PROG_OBJS) $(DOCDIR)/*.8.gz $(DOCDIR)/*.in

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


