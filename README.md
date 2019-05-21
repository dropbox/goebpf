# Go eBPF
[![Build Status](https://travis-ci.org/dropbox/goebpf.svg?branch=master)](https://travis-ci.org/dropbox/goebpf)
[![Go Report Card](https://goreportcard.com/badge/github.com/dropbox/goebpf)](https://goreportcard.com/report/github.com/dropbox/goebpf)
[![Documentation](https://godoc.org/github.com/dropbox/goebpf?status.svg)](http://godoc.org/github.com/dropbox/goebpf)

A nice and convenient way to work with `eBPF` programs from Go.

## Requirements
- Go 1.9+
- Linux Kernel 4.15+

## Supported eBPF program types
Currently only one program supported:
- `XDP`

Support for other types of program can be added in future. Feel free to contribute :)

## Installation
```bash
# Main library
go get github.com/dropbox/goebpf

# Mock version (if needed)
go get github.com/dropbox/goebpf/goebpf_mock
```

## Quick start
Consider very simple example of Read / Load / Attach
```go
    // In order to be simple this examples does not handle errors
    bpf := goebpf.NewDefaultEbpfSystem()
    // Read clang compiled binary
    bpf.LoadElf("test.elf")
    // Load XDP program into kernel
    xdp.Load()
    // Attach to interface
    xdp.Attach("eth0")
    defer xdp.Detach()
    // Work with maps
    test := bpf.GetMapByName("test")
    value, _ := test.LookupInt(0)
    fmt.Printf("Value at index 0 of map 'test': %d\n", )
```
Like it? Check our [examples](https://github.com/dropbox/goebpf/tree/master/examples/)

## Good readings
- [Cilium BPF and XDP Reference Guide](https://docs.cilium.io/en/latest/bpf/)
- [Prototype Kernel: XDP](https://prototype-kernel.readthedocs.io/en/latest/networking/XDP/index.html)
- [AF_XDP: Accelerating networking](https://lwn.net/Articles/750845/)
- [eBPF, part 1: Past, Present, and Future](https://ferrisellis.com/posts/ebpf_past_present_future/)
- [eBPF, part 2: Syscall and Map Types](https://ferrisellis.com/posts/ebpf_syscall_and_maps/)
