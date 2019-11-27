// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/dropbox/goebpf"
)

var iface = flag.String("iface", "", "Interface to bind XDP program to")
var elf = flag.String("elf", "ebpf_prog/xdp_dump.elf", "clang/llvm compiled binary file")
var programName = flag.String("program", "xdp_dump", "Name of XDP program (function name)")

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

	// Find special "PERF_EVENT" eBPF map
	perfmap := bpf.GetMapByName("perfmap")
	if perfmap == nil {
		fatalError("eBPF map 'perfmap' not found")
	}

	// Program name matches function name in xdp.c:
	//      int xdp_dump(struct xdp_md *ctx)
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

	perf, _ := goebpf.NewPerfEvent(perfmap)

	perfUpdates, err := perf.Start(0)
	if err != nil {
		fatalError("perf.Start(): %v", err)
	}
	defer perf.Stop()

	type Srcs struct {
		Src, Dst, Size uint32
	}

	var last uint32
	missed := 0
	for {
		select {
		case upd := <-perfUpdates:
			reader := bytes.NewReader(upd)
			var data Srcs
			binary.Read(reader, binary.LittleEndian, &data)
			fmt.Printf("src=%x dst=%d sz=%d\n", data.Src, data.Dst, data.Size)
			if data.Dst > last+1 {
				fmt.Println("MISSSS")
				missed++
			}
			last = data.Dst
		case <-ctrlC:
			fmt.Println("missed", missed)
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
		m := item.(*goebpf.EbpfMap)
		fmt.Printf("\t%s: %v, Fd %v\n", m.Name, m.Type, m.GetFd())
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
