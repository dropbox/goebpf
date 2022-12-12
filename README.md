# Go eBPF
[![Build Status](https://github.com/dropbox/goebpf/actions/workflows/go.yml/badge.svg)](https://github.com/dropbox/goebpf/actions?query=branch%3Amaster)
[![Go Report Card](https://goreportcard.com/badge/github.com/dropbox/goebpf)](https://goreportcard.com/report/github.com/dropbox/goebpf)
[![Documentation](https://godoc.org/github.com/dropbox/goebpf?status.svg)](http://godoc.org/github.com/dropbox/goebpf)

A nice and convenient way to work with `eBPF` programs / perf events from Go.

## Requirements
- Go 1.11+
- Linux Kernel 4.15+

## Supported eBPF features
- eBPF programs
    - `SocketFilter`
    - `XDP`
    - `Kprobe` / `Kretprobe`
    - `tc-cls` (`tc-act` is partially implemented, currently)
- Perf Events

Support for other program types / features can be added in future.
Meanwhile your contributions are warmly welcomed.. :)

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
    // Load XDP program into kernel (name matches function name in C)
    xdp := bpf.GetProgramByName("xdp_test")
    xdp.Load()
    // Attach to interface
    xdp.Attach("eth0")
    defer xdp.Detach()
    // Work with maps
    test := bpf.GetMapByName("test")
    value, _ := test.LookupInt(0)
    fmt.Printf("Value at index 0 of map 'test': %d\n", value)
```
Like it? Check our [examples](https://github.com/dropbox/goebpf/tree/master/examples/)

## Perf Events
Currently library has support for one, most popular use case of `perf_events: where `eBPF` map key maps to `cpu_id`.
So `eBPF` and `go` parts actually bind `cpu_id` to map index. It maybe as simple as:

```c
    // Define special, perf_events map where key maps to CPU_ID
    BPF_MAP_DEF(perfmap) = {
        .map_type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
        .max_entries = 128,     // Max supported CPUs
    };
    BPF_MAP_ADD(perfmap);

    // ...

    // Emit perf event with "data" to map "perfmap" where index is current CPU_ID
    bpf_perf_event_output(ctx, &perfmap, BPF_F_CURRENT_CPU, &data, sizeof(data));
```

And the `go` part:
```go
    perf, err := goebpf.NewPerfEvents("perfmap")
    // 4096 is ring buffer size
    perfEvents, err := perf.StartForAllProcessesAndCPUs(4096)
    defer perf.Stop()

    for {
        select {
            case data := <-perfEvents:
                fmt.Println(data)
        }
    }
```
Looks simple? Check our [full XDP dump example](https://github.com/dropbox/goebpf/tree/master/examples/xdp/xdp_dump)

## Kprobes
Library currently has support for `kprobes` and `kretprobes`.
It can be as simple as:

```c
    // kprobe handler function
    SEC("kprobe/guess_execve")
    int execve_entry(struct pt_regs *ctx) {
      // ...
      buf_perf_output(ctx);
      return 0;
    }
```
And the `go` part:
```go
	// Cleanup old probes
	err := goebpf.CleanupProbes()

	// Attach all probe programs
	for _, prog := range bpf.GetPrograms() {
		err := prog.Attach(nil)
	}

	// Create perf events
	eventsMap := p.bpf.GetMapByName("events")
	p.pe, err = goebpf.NewPerfEvents(eventsMap)
	events, err := p.pe.StartForAllProcessesAndCPUs(4096)
	defer events.Stop()

	for {
		select {
		case data := <-events:
			fmt.Println(data) // kProbe event
		}
	}
```
Simple? Check [exec dump example](https://github.com/dropbox/goebpf/tree/master/examples/kprobe/exec_dump)

## Good readings
- [XDP Tutorials](https://github.com/xdp-project/xdp-tutorial)
- [Cilium BPF and XDP Reference Guide](https://docs.cilium.io/en/latest/bpf/)
- [Prototype Kernel: XDP](https://prototype-kernel.readthedocs.io/en/latest/networking/XDP/index.html)
- [AF_XDP: Accelerating networking](https://lwn.net/Articles/750845/)
- [eBPF, part 1: Past, Present, and Future](https://ferrisellis.com/posts/ebpf_past_present_future/)
- [eBPF, part 2: Syscall and Map Types](https://ferrisellis.com/posts/ebpf_syscall_and_maps/)
- [Oracle Blog: A Tour of eBPF Program Types](https://blogs.oracle.com/linux/notes-on-bpf-1)
- [Oracle Blog: eBPF Helper Functions](https://blogs.oracle.com/linux/notes-on-bpf-2)
- [Oracle Blog: Communicating with Userspace](https://blogs.oracle.com/linux/notes-on-bpf-3)
