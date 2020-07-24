// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

/*
Package goebpf provides simple and convenient interface to Linux eBPF system.

Overview

Extended Berkeley Packet Filter (eBPF) is a highly flexible and efficient virtual machine
in the Linux kernel allowing to execute bytecode at various hook points in a safe manner.
It is actually close to kernel modules which can provide the same functionality,
but without cost of kernel panic if something went wrong.

The library is intended to simplify work with eBPF programs.
It takes care of low level routine implementation to make it easy to load/run/manage eBPF programs.
Currently supported functionality:
- Read / parse clang/llmv compiled binaries for eBPF programs / maps
- Creates / loads eBPF program / eBPF maps into kernel
- Provides simple interface to interact with eBPF maps
- Has mock versions of eBPF objects (program, map, etc) in order to make writing unittests simple.

XDP

eXpress Data Path - provides a bare metal, high performance, programmable packet processing
at the closest at possible point to network driver. That makes it ideal for speed without
compromising programmability. Key benefits includes following:

- It does not require any specialized hardware (program works in kernel’s "VM")
- It does not require kernel bypass
- It does not replace the TCP/IP stack

Considering very simple and highly effective way to DROP all packets from given source IPv4 address:

XDP program (written in C):

	// Simple map to count dropped packets
	BPF_MAP_DEF(drops) = {
	    .map_type = BPF_MAP_TYPE_PERCPU_ARRAY,
	    .key_size = 4,
	    .value_size = 8,
	    .max_entries = 1,
	};
	BPF_MAP_ADD(drops);

	SEC("xdp")
	int xdp_drop(struct xdp_md *ctx)
	{
	    if (found) { // If some condition (e.g. SRC IP) matches...
	        __u32 idx = 0;
	        // Increase stat by 1
	        __u64 *stat = bpf_map_lookup_elem(&drops, &idx);
	        if (stat) {
	            *stat += 1;
	        }
	        return XDP_DROP;
	    }
	    return XDP_PASS;
	}

Once compiled can be used by goebpf in the following way:

	bpf := goebpf.NewDefaultEbpfSystem()
	err := bpf.LoadElf("xdp.elf")
	program := bpf.GetProgramByName("xdp_drop") // name matches function name in C
	err = program.Load() // Load program into kernel
	err = program.Attach("eth0") // Attach to interface
	defer program.Detach()

	// Interact with program is simply done through maps:
	drops := bpf.GetMapByName("drops") // name also matches BPF_MAP_ADD(drops)
	val, err := drops.LookupInt(0) // Get value from map at index 0
	if err == nil {
	    fmt.Printf("Drops: %d\n", val)
	}

PerfEvents

Perf Events (originally Performance Counters for Linux) is powerful kernel instrument for
tracing, profiling and a lot of other cases like general events to user space.

Usually it is implemented using special eBPF map type "BPF_MAP_TYPE_PERF_EVENT_ARRAY" as
a container to send events into.

A simple example could be to log all TCP SYN packets into user space from XDP program:

	BPF_MAP_DEF(perfmap) = {
		.map_type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
		.max_entries = 128,  // Up to 128 CPUs
	};
	BPF_MAP_ADD(perfmap);

	SEC("xdp")
	int xdp_dump(struct xdp_md *ctx) {
		// ...
		if (tcp->syn) {
			// Log event to user space
			bpf_perf_event_output(ctx, &perfmap, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
		}
	}


	bpf := goebpf.NewDefaultEbpfSystem()
	bpf.LoadElf("xdp.elf")
	program := bpf.GetProgramByName("xdp_dump") // name matches function name in C
	err = program.Load() // Load program into kernel
	err = program.Attach("eth0") // Attach to interface
	defer program.Detach()

	// Start listening to Perf Events
	perf, err := goebpf.NewPerfEvents(perfmap)
	// 4096 is ring buffer size
	perfEvents, err := perf.StartForAllProcessesAndCPUs(4096)
	defer perf.Stop()

	for {
		select {
			case eventData := <-perfEvents:
				fmt.Println(eventData)
		}
	}

Kprobes

There are currently two types of supported probes: kprobes, and kretprobes
(also called return probes). A kprobe can be inserted on virtually
any instruction in the kernel. A return probe fires when a specified
function returns.

For example, you can trigger eBPF code to run when a kernel function starts
by attaching the program to a “kprobe” event. Because it runs in the kernel,
eBPF code is extremely high performance.

A simple example could be to log all process execution events into user space
from Kprobe program:

	BPF_MAP_DEF(events) = {
		.map_type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
		.max_entries = 1024,
	};
	BPF_MAP_ADD(events);

	SEC("kprobe/guess_execve")
	int execve_entry(struct pt_regs *ctx) {
		// ...
		event_t e = {0};
		e.ktime_ns = bpf_ktime_get_ns();
		e.pid = bpf_get_current_pid_tgid() >> 32;
		e.uid = bpf_get_current_uid_gid() >> 32;
		e.gid = bpf_get_current_uid_gid();
		bpf_get_current_comm(&e.comm, sizeof(e.comm));

		buf_write(buf, (void *)&e, sizeof(e));
		buf_strcat(buf, (void *)args[0]);
		buf_strcat_argv(buf, (void *)args[1]);
		buf_perf_output(ctx);

		return 0;
	}


	// Cleanup old probes
	err := goebpf.CleanupProbes()

	// Load eBPF compiled binary
	bpf := goebpf.NewDefaultEbpfSystem()
	bpf.LoadElf("kprobe.elf")
	program := bpf.GetProgramByName("kprobe") // name matches function name in C

	// Attach kprobes
	err = p.AttachProbes()
	// Detach them once done
	defer p.DetachProbes()
*/
package goebpf
