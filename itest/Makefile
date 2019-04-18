# Copyright (c) 2019 Dropbox, Inc.
# Full license can be found in the LICENSE file.

GOCMD := go
GOBUILD := $(GOCMD) build
GOCLEAN := $(GOCMD) clean
GOTEST := $(GOCMD) test
GOGET := $(GOCMD) get

TEST_SOURCE := $(wildcard *.go)
TEST_BINARY := ./itest_test

EBPF_SOURCE := ebpf_prog/xdp1.c
EBPF_BINARY := ebpf_prog/xdp1.elf

EUID := $(shell id -u -r)

all: build_test build_bpf

$(EBPF_BINARY): $(EBPF_SOURCE)
	clang -I.. -O2 -target bpf -c $^  -o $@

$(TEST_BINARY): $(TEST_SOURCE)
	$(GOTEST) -c -v -o $@

build_test: $(TEST_BINARY)
build_bpf: $(EBPF_BINARY)

check_root:
ifneq ($(EUID),0)
	@echo "\nPlease run as root user in order to work with eBPF maps / programs.\n"
	@exit 1
endif

clean:
	$(GOCLEAN)
	rm -f $(TEST_BINARY)
	rm -f $(EBPF_BINARY)

test: check_root build_bpf build_test
	@ulimit -l unlimited
	@mount bpf -t bpf /sys/fs/bpf
	./$(TEST_BINARY) -test.v
	@umount /sys/fs/bpf

run: test
