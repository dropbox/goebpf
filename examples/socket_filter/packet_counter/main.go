// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"golang.org/x/sys/unix"

	"github.com/dropbox/goebpf"
)

const (
	SO_BINDTODEVICE = 25
)

var elf = flag.String("elf", "ebpf_prog/sock_filter.elf", "clang/llvm compiled binary file")
var programName = flag.String("program", "packet_counter", "Name of SocketFilter program (function name)")
var iface = flag.String("iface", "", "Interface to open raw socket on")

func main() {
	flag.Parse()
	if *iface == "" {
		fatalError("Interface (-iface) is required.")
	}

	// Create eBPF system / load .ELF file compiled by clang/llvm
	bpf := goebpf.NewDefaultEbpfSystem()
	err := bpf.LoadElf(*elf)
	if err != nil {
		fatalError("LoadElf() failed: %v", err)
	}
	printBpfInfo(bpf)

	// Find counter eBPF map
	counter := bpf.GetMapByName("counter")
	if counter == nil {
		fatalError("eBPF map 'counter' not found")
	}

	// Program name matches function name in socket_filter.c:
	//      int packet_counter(struct __sk_buff *skb)
	sf := bpf.GetProgramByName(*programName)
	if sf == nil {
		fatalError("Program '%s' not found.", *programName)
	}

	// Load SocketFilter program into kernel
	err = sf.Load()
	if err != nil {
		fatalError("sf.Load(): %v", err)
	}

	// Create RAW socket
	sock, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, unix.ETH_P_ALL<<8) // htons(unix.ETH_P_ALL)
	if err != nil {
		fatalError("unable to create raw socket: %v", err)
	}
	defer unix.Close(sock)

	// Bind raw socket to interface
	err = unix.SetsockoptString(sock, unix.SOL_SOCKET, SO_BINDTODEVICE, *iface)
	if err != nil {
		fatalError("SO_BINDTODEVICE to %s failed: %v", *iface, err)
	}

	// Attach eBPF program to socket as socketFilter
	err = sf.Attach(goebpf.SocketFilterAttachParams{
		SocketFd:   sock,
		AttachType: goebpf.SocketAttachTypeFilter,
	})

	if err != nil {
		fatalError("sf.Attach(): %v", err)
	}
	defer sf.Detach()

	// Add CTRL+C handler
	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, os.Interrupt)

	// Print stat every second / exit on CTRL+C
	fmt.Println("SocketFilter program successfully loaded and attached. Counters refreshed every second.")
	fmt.Println()
	ticker := time.NewTicker(1 * time.Second)
	for {
		select {
		case <-ticker.C:
			value, err := counter.LookupInt(0)
			if err != nil {
				fatalError("LookupInt failed: %v", err)
			}
			fmt.Printf(" Packets: %d\r", value)
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
