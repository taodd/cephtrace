CLANG := clang
CXX := g++
OUTPUT := .output
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')
#BPFTOOL ?= /usr/local/sbin/bpftool

OSDTRACE_SRC = $(abspath ./src)

BPFTOOL_OUTPUT ?= $(abspath $(OUTPUT)/bpftool)
BPFTOOL ?= $(BPFTOOL_OUTPUT)/bootstrap/bpftool
BPFTOOL_SRC = $(abspath ./bpftool/src)

OSDTRACE_OBJS = $(OUTPUT)/dwarf_parser.o $(OUTPUT)/osdtrace.o

RADOSTRACE_OBJS = $(OUTPUT)/dwarf_parser.o $(OUTPUT)/radostrace.o

LIBBPF_TOP = $(abspath ./libbpf)
LIBBPF_SRC = $(LIBBPF_TOP)/src

LIBBPF_UAPI_INCLUDES = -I $(LIBBPF_TOP)/include/uapi
#LIBBPF_INCLUDES = -I $(LIBBPF_TOP)/include
#LIBBPF_LIBS = -L /usr/local/bpf/lib64 -lbpf
LIBBPF_OBJ = $(abspath $(OUTPUT)/libbpf.a) 

INCLUDES = -I$(OUTPUT) $(LIBBPF_UAPI_INCLUDES) -I$(LIBBPF_SRC)

CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 | sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'					\
		      "$(1)"						\
		      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"	\
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

all: build

build: osdtrace radostrace 

.PHONY: clean
clean:
	$(call msg,CLEAN)
	rm -rf $(OUTPUT) osdtrace radostrace
$(OUTPUT) $(OUTPUT)/libbpf $(BPFTOOL_OUTPUT):
	$(call msg,MKDIR,$@)
	mkdir -p $@

# Build libbpf
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	make -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		      \
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)		      \
		    INCLUDEDIR= LIBDIR= UAPIDIR=			      \
		    install

# Build bpftool
$(BPFTOOL): | $(BPFTOOL_OUTPUT)
	$(call msg,BPFTOOL,$@)
	make ARCH= CROSS_COMPILE= OUTPUT=$(BPFTOOL_OUTPUT)/ -C $(BPFTOOL_SRC) bootstrap

# Build BPF Code
$(OUTPUT)/%.bpf.o: $(OSDTRACE_SRC)/%.bpf.c $(LIBBPF_OBJ) | $(OUTPUT) $(BPFTOOL)
	$(call msg,BPF,$@)
	$(CLANG)  -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c $< -o $(patsubst %.bpf.o,%.tmp.bpf.o,$@) 
	$(BPFTOOL) gen object $@ $(patsubst %.bpf.o,%.tmp.bpf.o,$@)

# Generate BPF skeletons
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT) $(BPFTOOL)
	$(call msg,GEN-SKEL,$@)
	$(BPFTOOL) gen skeleton $< > $@

$(OUTPUT)/osdtrace.o: $(OSDTRACE_SRC)/osdtrace.cc $(OSDTRACE_SRC)/*.h $(OUTPUT)/osdtrace.skel.h | $(OUTPUT) $(LIBBPF_OBJ)
	$(CXX) -g $(INCLUDES) -c -o $@ $<

$(OUTPUT)/radostrace.o: $(OSDTRACE_SRC)/radostrace.cc $(OSDTRACE_SRC)/*.h $(OUTPUT)/radostrace.skel.h | $(OUTPUT) $(LIBBPF_OBJ)
	$(CXX) -g $(INCLUDES) -c -o $@ $<


$(OUTPUT)/dwarf_parser.o: $(OSDTRACE_SRC)/dwarf_parser.cc $(OSDTRACE_SRC)/*.h $(OUTPUT)/osdtrace.skel.h | $(OUTPUT) $(LIBBPF_OBJ)
	$(CXX) -g $(INCLUDES) -c -o $@ $<

# Generate osdtrace
#osdtrace: $(OSDTRACE_SRC)/osdtrace.cc $(OSDTRACE_SRC)/*.h $(OUTPUT)/osdtrace.skel.h $(LIBBPF_OBJ) | $(OUTPUT)
#	$(CXX)  -g -O2 -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -o $@ $< $(LIBBPF_OBJ) -lelf -ldw -lz

osdtrace: $(OUTPUT)/osdtrace.o $(OUTPUT)/dwarf_parser.o $(OUTPUT)/osdtrace.skel.h $(LIBBPF_OBJ) | $(OUTPUT)
	$(CXX)  -g -O2 -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -o $@ $(OSDTRACE_OBJS) $(LIBBPF_OBJ) -lelf -ldw -lz

radostrace: $(OUTPUT)/radostrace.o $(OUTPUT)/dwarf_parser.o $(OUTPUT)/radostrace.skel.h $(LIBBPF_OBJ) | $(OUTPUT)
	$(CXX)  -g -O2 -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -o $@ $(RADOSTRACE_OBJS) $(LIBBPF_OBJ) -lelf -ldw -lz


