// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dropbox/goebpf"
)

var iface = flag.String("iface", "", "Interface to bind XDP program to")
var elf = flag.String("elf", "ebpf_prog/xdp.elf", "clang/llvm compiled binary file")
var programName = flag.String("program", "packet_count", "Name of XDP program (function name)")

func main() {
	flag.Parse()
	if *iface == "" {
		fatalError("-iface is required.")
	}

	// Create eBPF system / load .ELF files compiled by clang/llvm
	bpf := goebpf.NewDefaultEbpfSystem()
	err := bpf.LoadElf(*elf)
	if err != nil {
		fatalError("LoadElf() failed: %v", err)
	}
	printBpfInfo(bpf)

	// Find protocols eBPF map
	protocols := bpf.GetMapByName("protocols")
	if protocols == nil {
		fatalError("eBPF map 'protocols' not found")
	}

	// Program name matches function name in xdp.c:
	//      int packet_count(struct xdp_md *ctx)
	xdp := bpf.GetProgramByName(*programName)
	if xdp == nil {
		fatalError("Program '%s' not found.", *programName)
	}

	// Load XDP program into kernel
	err = xdp.Load()
	if err != nil {
		fatalError("xdp.Load(): %v", err)
	}

	// Attach to interface
	err = xdp.Attach(*iface)
	if err != nil {
		fatalError("xdp.Attach(): %v", err)
	}
	defer xdp.Detach()

	// Add CTRL+C handler
	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, os.Interrupt)

	// Print stat every second / exit on CTRL+C
	fmt.Println("XDP program successfully loaded and attached. Counters refreshed every second.")
	fmt.Println()
	ticker := time.NewTicker(1 * time.Second)
	for {
		select {
		case <-ticker.C:
			// Print only first 132 numbers (HOPOPT - SCTP)
			for i := 0; i < 132; i++ {
				value, err := protocols.LookupInt(i)
				if err != nil {
					fatalError("LookupInt failed: %v", err)
				}
				if value > 0 {
					fmt.Printf("%s: %d ", getProtoName(i), value)
				}
			}
			fmt.Printf("\r")
		case <-ctrlC:
			fmt.Println("\nDetaching program and exit")
			return
		}
	}
}

func fatalError(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func printBpfInfo(bpf goebpf.System) {
	fmt.Println("Maps:")
	for _, item := range bpf.GetMaps() {
		fmt.Printf("\t%s: %v, Fd %v\n", item.GetName(), item.GetType(), item.GetFd())
	}
	fmt.Println("\nPrograms:")
	for _, prog := range bpf.GetPrograms() {
		fmt.Printf("\t%s: %v, size %d, license \"%s\"\n",
			prog.GetName(), prog.GetType(), prog.GetSize(), prog.GetLicense(),
		)

	}
	fmt.Println()
}

// Converts IPPROTO number into string for well known protocols
func getProtoName(proto int) string {
	switch proto {
	case syscall.IPPROTO_ENCAP:
		return "IPPROTO_ENCAP"
	case syscall.IPPROTO_GRE:
		return "IPPROTO_GRE"
	case syscall.IPPROTO_ICMP:
		return "IPPROTO_ICMP"
	case syscall.IPPROTO_IGMP:
		return "IPPROTO_IGMP"
	case syscall.IPPROTO_IPIP:
		return "IPPROTO_IPIP"
	case syscall.IPPROTO_SCTP:
		return "IPPROTO_SCTP"
	case syscall.IPPROTO_TCP:
		return "IPPROTO_TCP"
	case syscall.IPPROTO_UDP:
		return "IPPROTO_UDP"
	default:
		return fmt.Sprintf("%v", proto)
	}
}
