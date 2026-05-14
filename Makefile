VERSION := 1.6
DATE ?= $(shell date +%Y-%m-%d)
SRC_TGT := release

# Git metadata for the --version banner. These resolve to empty strings on
# release-tarball builds (no .git/ present) which is exactly what
# print_tool_version() uses to distinguish "release" from "development".
GIT_DESCRIBE := $(shell git describe --tags --dirty --always 2>/dev/null)
GIT_BRANCH   := $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null)

# Defines applied only when compiling src/version_utils.cc — keeps every
# other translation unit cache-friendly even when git state changes.
VERSION_DEFINES := \
    -DCEPHTRACE_VERSION='"$(VERSION)"' \
    -DCEPHTRACE_BUILD_DATE='"$(DATE)"' \
    -DCEPHTRACE_GIT_DESCRIBE='"$(GIT_DESCRIBE)"' \
    -DCEPHTRACE_GIT_BRANCH='"$(GIT_BRANCH)"'
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
COMMON_OBJS := $(OUTPUT)/dwarf_parser.o $(OUTPUT)/version_utils.o
PROG_OBJS := osdtrace radostrace kfstrace
PROG_SRCS := $(addprefix $(OSDTRACE_SRC)/,$(addsuffix .cc,$(PROG_OBJS)))
PROG_BPF_SRCS := $(addprefix $(OSDTRACE_SRC)/,$(addsuffix .bpf.c,$(PROG_OBJS)))

# Auto-generated embedded DWARF data header.
# JSON paths may contain ':' (Ceph epoch notation) which Make treats as the
# target/prereq separator — escape with backslash so it's a literal filename.
EMBEDDED_DWARF_HDR := $(OSDTRACE_SRC)/embedded_dwarf_data.h
EMBEDDED_DWARF_GEN := tools/generate_embedded_dwarf.py
EMBEDDED_DWARF_JSON := $(shell find files -name '*.json' 2>/dev/null | sed 's/:/\\:/g')

# Include paths
INCLUDES := -I$(OUTPUT) \
           -I$(LIBBPF_TOP)/include/uapi \
           -I$(LIBBPF_SRC) \
           -I$(abspath ./external/json/include)

# Compiler flags
CLANG_BPF_SYS_INCLUDES := $(shell $(CLANG) -v -E - </dev/null 2>&1 | \
    sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')
CXXFLAGS := -g -O2 -Wall -Wextra -Wno-unused-function -Wno-address-of-packed-member -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES)
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
.PHONY: all clean clang-tidy
all: $(OSDTRACE_SRC)/ceph_btf_local.h $(EMBEDDED_DWARF_HDR) $(PROG_OBJS)

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
	$(Q)rm -rf $(OUTPUT) $(PROG_OBJS) $(DOCDIR)/*.8.gz $(DOCDIR)/*.in $(OSDTRACE_SRC)/ceph_btf_local.h $(EMBEDDED_DWARF_HDR)

# clang-tidy static analysis (requires skeleton headers in .output/)
CLANG_TIDY ?= clang-tidy
TIDY_SRCS := $(OSDTRACE_SRC)/osdtrace.cc \
             $(OSDTRACE_SRC)/radostrace.cc \
             $(OSDTRACE_SRC)/kfstrace.cc \
             $(OSDTRACE_SRC)/dwarf_parser.cc \
             $(OSDTRACE_SRC)/version_utils.cc

clang-tidy: $(OUTPUT)/osdtrace.skel.h $(OUTPUT)/radostrace.skel.h $(OUTPUT)/kfstrace.skel.h $(EMBEDDED_DWARF_HDR)
	$(call msg,TIDY)
	$(Q)for src in $(TIDY_SRCS); do \
		printf '  %-8s %s\n' "TIDY" "$$src"; \
		$(CLANG_TIDY) $$src -- $(CXXFLAGS) $(VERSION_DEFINES) || exit 1; \
	done

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

# Generate Ceph BTF header
$(OSDTRACE_SRC)/ceph_btf_local.h: | $(OUTPUT) $(BPFTOOL)
	@$(call msg,GEN-BTF,$@)
	@set -eu; \
	src=""; tmp=""; \
	CEPH_KO=$$(find /lib/modules/$$(uname -r) -type f -name 'ceph.ko*' 2>/dev/null | head -1); \
	[ -n "$$CEPH_KO" ] || { echo "No ceph.ko* found under /lib/modules/$$(uname -r)" >&2; exit 1; }; \
	echo "Found ceph kernel module: $$CEPH_KO"; \
	case "$$CEPH_KO" in \
		*.ko)     src="$$CEPH_KO";; \
		*.ko.xz)  tmp=$$(mktemp); xz -v -dc "$$CEPH_KO" >"$$tmp"; src="$$tmp";; \
		*.ko.zst) tmp=$$(mktemp); zstd -v -dc --no-progress "$$CEPH_KO" >"$$tmp"; src="$$tmp";; \
	esac; \
	$(BPFTOOL) btf dump file "$$src" format c --base-btf /sys/kernel/btf/vmlinux >"$@"; \
	rm -fv $$tmp; \

# Build BPF objects and skeletons
$(OUTPUT)/kfstrace.bpf.o: $(OSDTRACE_SRC)/kfstrace.bpf.c $(OSDTRACE_SRC)/ceph_btf_local.h $(LIBBPF_OBJ) | $(OUTPUT) $(BPFTOOL)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf $(CXXFLAGS) -c $< -o $(patsubst %.bpf.o,%.tmp.bpf.o,$@)
	$(Q)$(BPFTOOL) gen object $@ $(patsubst %.bpf.o,%.tmp.bpf.o,$@)

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

# Generate embedded DWARF data header from JSON files in files/
$(EMBEDDED_DWARF_HDR): $(EMBEDDED_DWARF_GEN) $(EMBEDDED_DWARF_JSON)
	$(call msg,GEN-DWARF,$@)
	$(Q)python3 $(EMBEDDED_DWARF_GEN)

# Special rule for dwarf_parser.o since it doesn't need a skel.h
$(OUTPUT)/dwarf_parser.o: $(OSDTRACE_SRC)/dwarf_parser.cc $(OUTPUT)/osdtrace.skel.h $(EMBEDDED_DWARF_HDR) $(OSDTRACE_SRC)/*.h | $(OUTPUT) $(LIBBPF_OBJ)
	$(call msg,CXX,$@)
	$(Q)$(CXX) $(CXXFLAGS) -c -o $@ $<

# Special rule for version_utils.o since it doesn't need a skel.h.
# Depends on FORCE so the git describe / build-date macros are always
# re-evaluated — otherwise an unchanged source file would keep stale
# metadata in the binary across commits.
.PHONY: FORCE
FORCE:

$(OUTPUT)/version_utils.o: $(OSDTRACE_SRC)/version_utils.cc $(OSDTRACE_SRC)/*.h FORCE | $(OUTPUT) $(LIBBPF_OBJ)
	$(call msg,CXX,$@)
	$(Q)$(CXX) $(CXXFLAGS) $(VERSION_DEFINES) -c -o $@ $<


# Special rule for kfstrace.o since it doesn't need dwarf_parser
$(OUTPUT)/kfstrace.o: $(OSDTRACE_SRC)/kfstrace.cc $(OSDTRACE_SRC)/bpf_ceph_types.h $(OUTPUT)/kfstrace.skel.h | $(OUTPUT) $(LIBBPF_OBJ)
	$(call msg,CXX,$@)
	$(Q)$(CXX) $(CXXFLAGS) -c -o $@ $<

# Build final executables
define build_rule
$(1): $(OUTPUT)/$(1).o $(COMMON_OBJS) $(OUTPUT)/$(1).skel.h $(LIBBPF_OBJ) | $(OUTPUT)
	$$(call msg,LINK,$$@)
	$(Q)$$(CXX) $$(CXXFLAGS) -o $$@ $$< $$(COMMON_OBJS) $$(LIBS)
endef

# Special rule for kfstrace - doesn't need dwarf_parser, but does pull in
# version_utils for the shared --version banner.
kfstrace: $(OUTPUT)/kfstrace.o $(OUTPUT)/version_utils.o $(OUTPUT)/kfstrace.skel.h $(LIBBPF_OBJ) | $(OUTPUT)
	$(call msg,LINK,$@)
	$(Q)$(CXX) $(CXXFLAGS) -o $(DESTDIR)$@ $< $(OUTPUT)/version_utils.o $(LIBBPF_OBJ) -lelf -lz -ldl

# Apply build rule to other programs (osdtrace and radostrace)
$(foreach prog,$(filter-out kfstrace,$(PROG_OBJS)),$(eval $(call build_rule,$(prog))))


