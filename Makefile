CLANG := clang
CXX := g++
OUTPUT := .
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')
BPFTOOL ?= /usr/local/sbin/bpftool

LIBBPF_TOP = /home/taodd/Git/libbpf

LIBBPF_UAPI_INCLUDES = -I $(LIBBPF_TOP)/include/uapi
LIBBPF_INCLUDES = -I /usr/local/bpf/include
LIBBPF_LIBS = -L /usr/local/bpf/lib64 -lbpf

INCLUDES =  $(LIBBPF_UAPI_INCLUDES) $(LIBBPF_INCLUDES)

CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 | sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

$(shell mkdir -p $(OUTPUT))

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

build: osdtrace 

.PHONY: clean
clean:
	$(call msg,CLEAN)
	rm -rf *skel.h *.o
##$(OUTPUT) $(OUTPUT)/libbpf $(BPFTOOL_OUTPUT):
#	$(call msg,MKDIR,$@)
#	$(shell mkdir -p $@)

# Build libbpf

# Build bpftool

# Build BPF Code
%.bpf.o: %.bpf.c
	$(call msg,BPF,$@)
	$(CLANG)  -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c $< -o $(patsubst %.bpf.o,%.tmp.bpf.o,$@) 
	$(BPFTOOL) gen object $@ $(patsubst %.bpf.o,%.tmp.bpf.o,$@)

# Generate BPF skeletons
%.skel.h: %.bpf.o
	$(call msg,GEN-SKEL,$@)
	$(BPFTOOL) gen skeleton $< > $@

# Generate osdtrace
osdtrace: uprobe_osd.cc uprobe_osd.skel.h
	$(CXX)  -g -O2 -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -o osdtrace uprobe_osd.cc $(LIBBPF_LIBS) -lbpf -lelf -ldw -lz
	


