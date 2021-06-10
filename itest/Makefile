# Copyright (c) 2019 Dropbox, Inc.
# Full license can be found in the LICENSE file.

GOCMD := go
GOBUILD := $(GOCMD) build
GOCLEAN := $(GOCMD) clean
GOTEST := $(GOCMD) test
GOGET := $(GOCMD) get

TEST_SOURCE := $(wildcard *.go)
TEST_BINARY := ./itest_test

EBPF_XDP_SOURCE := ebpf_prog/xdp1.c
EBPF_XDP_BINARY := ebpf_prog/xdp1.elf
EBPF_KPROBE_SOURCE := ebpf_prog/kprobe1.c
EBPF_KPROBE_BINARY := ebpf_prog/kprobe1.elf
EBPF_TC_SOURCE := ebpf_prog/tc1.c
EBPF_TC_BINARY := ebpf_prog/tc1.elf

EUID := $(shell id -u -r)

all: build_test build_bpf

$(EBPF_XDP_BINARY): $(EBPF_XDP_SOURCE)
	clang -I.. -O2 -target bpf -c $^  -o $@

$(EBPF_KPROBE_BINARY): $(EBPF_KPROBE_SOURCE)
	clang -I.. -O2 -target bpf -c $^  -o $@

$(EBPF_TC_BINARY): $(EBPF_TC_SOURCE)
	clang -I.. -O2 -target bpf -c $^  -o $@

$(TEST_BINARY): $(TEST_SOURCE)
	$(GOTEST) -c -v -o $@

build_test: $(TEST_BINARY)
build_bpf: $(EBPF_XDP_BINARY) $(EBPF_KPROBE_BINARY) $(EBPF_TC_BINARY)

check_root:
ifneq ($(EUID),0)
	@echo "\nPlease run as root user in order to work with eBPF maps / programs.\n"
	@exit 1
endif

clean:
	$(GOCLEAN)
	rm -f $(TEST_BINARY)
	rm -f $(EBPF_XDP_BINARY)
	rm -f $(EBPF_KPROBE_BINARY)
	rm -f $(EBPF_TC_BINARY)

test: check_root build_bpf build_test
	@ulimit -l unlimited
	@mount bpf -t bpf /sys/fs/bpf
	./$(TEST_BINARY) -test.v
	@umount /sys/fs/bpf

run: test
