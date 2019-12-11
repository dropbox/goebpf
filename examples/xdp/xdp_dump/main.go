// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"

	"github.com/dropbox/goebpf"
)

var iface = flag.String("iface", "", "Interface to bind XDP program to")
var elf = flag.String("elf", "ebpf_prog/xdp_dump.elf", "clang/llvm compiled binary file")
var programName = flag.String("program", "xdp_dump", "Name of XDP program (function name)")

const (
	// Size of structure used to pass metadata
	metadataSize = 12
)

// In sync with xdp_dump.c  "struct perf_event_item"
type perfEventItem struct {
	SrcIp, DstIp     uint32
	SrcPort, DstPort uint16
}

func main() {
	flag.Parse()
	if *iface == "" {
		fatalError("-iface is required.")
	}

	fmt.Println("\nXDP dump example program\n")

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

	// Start listening to Perf Events
	perf, _ := goebpf.NewPerfEvents(perfmap)
	perfEvents, err := perf.StartForAllProcessesAndCPUs(4096)
	if err != nil {
		fatalError("perf.StartForAllProcessesAndCPUs(): %v", err)
	}

	fmt.Println("XDP program successfully loaded and attached.")
	fmt.Println("All new TCP connection requests (SYN) coming to this host will be dumped here.")
	fmt.Println()

	go func() {
		var event perfEventItem
		for {
			if eventData, ok := <-perfEvents; ok {
				reader := bytes.NewReader(eventData)
				binary.Read(reader, binary.LittleEndian, &event)
				fmt.Printf("TCP: %v:%d -> %v:%d\n",
					intToIPv4(event.SrcIp), ntohs(event.SrcPort),
					intToIPv4(event.DstIp), ntohs(event.DstPort),
				)
				if len(eventData)-metadataSize > 0 {
					// event contains packet sample as well
					fmt.Println(hex.Dump(eventData[metadataSize:]))
				}
			} else {
				// Update channel closed
				break
			}
		}
	}()

	// Wait until Ctrl+C pressed
	<-ctrlC

	// Stop perf events and print summary
	perf.Stop()
	fmt.Println("\nSummary:")
	fmt.Printf("\t%d Event(s) Received\n", perf.EventsReceived)
	fmt.Printf("\t%d Event(s) lost (e.g. small buffer, delays in processing)\n", perf.EventsLost)
	fmt.Println("\nDetaching program and exit...")
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

func intToIPv4(ip uint32) net.IP {
	res := make([]byte, 4)
	binary.LittleEndian.PutUint32(res, ip)
	return net.IP(res)
}

func ntohs(value uint16) uint16 {
	return ((value & 0xff) << 8) | (value >> 8)
}
