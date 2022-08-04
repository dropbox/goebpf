# Copyright (c) 2019 Dropbox, Inc.
# Full license can be found in the LICENSE file.

GOCMD := go
GOBUILD := $(GOCMD) build
GOCLEAN := $(GOCMD) clean
CLANG := clang
CLANG_INCLUDE := -I../../..

GO_SOURCE := main.go
GO_BINARY := main

EBPF_HEADERS := $(wildcard ebpf_prog/*.h)
EBPF_SOURCE := $(wildcard ebpf_prog/*.c)
EBPF_BINARY := ebpf_prog/tc.elf

all: build_bpf build_go

build_bpf: $(EBPF_BINARY)

build_go: $(GO_BINARY)

clean:
	$(GOCLEAN)
	rm -f $(GO_BINARY)
	rm -f $(EBPF_BINARY)

$(EBPF_SOURCE): $(EBPF_HEADERS)

$(EBPF_BINARY): $(EBPF_SOURCE)
	$(CLANG) $(CLANG_INCLUDE) -O2 -target bpf -DGO_EBPF -c $^  -o $@

$(GO_BINARY): $(GO_SOURCE)
	$(GOBUILD) -v -o $@
