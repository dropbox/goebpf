// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/dropbox/goebpf"
)

var iface = flag.String("iface", "", "Interface to bind TC program to")
var elf = flag.String("elf", "ebpf_prog/tc.elf", "clang/llvm compiled binary file")
var ingressFunction = flag.String("ingress", "tc_ingress", "Name of tc program (function name) for ingress traffic")
var egressFunction = flag.String("egress", "tc_egress", "Name of tc program (function name) for egress traffic")

const (
	HASH_FLAG_DIR_INGRESS  = 0
	HASH_FLAG_DIR_EGRESS   = (1 << 0)
	HASH_FLAG_UNIT_PACKETS = 0
	HASH_FLAG_UNIT_BYTES   = (1 << 1)
)

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

	// Find metrics eBPF map
	metrics := bpf.GetMapByName("metrics")
	if metrics == nil {
		fatalError("eBPF map 'metrics' not found")
	}

	// entrypoints are
	// int tc_ingress(struct __sk_buff *skb)
	// int tc_egress(struct __sk_buff *skb)
	var programs = []struct {
		name      string
		direction goebpf.TcFlowDirection
	}{
		{*ingressFunction, goebpf.TcDirectionIngress},
		{*egressFunction, goebpf.TcDirectionEgress},
	}
	for _, prog := range programs {
		program := bpf.GetProgramByName(prog.name)

		if program == nil {
			fatalError("No programs of type 'SchedACT' not found.")
		}

		err = program.Load()
		if err != nil {
			fatalError("program.Load() failed: %v", err)
		}

		attachParams := &goebpf.TcAttachParams{
			Interface:    *iface,
			Direction:    prog.direction,
			DirectAction: false,
			EntryPoint:   prog.name,
			ClobberIngress: true,
		}

		err = program.Attach(attachParams)
		defer program.Detach()

		if err != nil {
			fatalError("Failed to attach %s program: %v", prog.direction.String(), err)
		}
	}

	// Add CTRL+C handler
	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, os.Interrupt)

	// Print stat every second / exit on CTRL+C
	fmt.Println("TC program successfully loaded and attached. Counters refreshed every second.")
	fmt.Println()
	ticker := time.NewTicker(1 * time.Second)
	for {
		select {
		case <-ticker.C:
			// clear the screen
			fmt.Print("\x1B[2J")
			// move cursor to top left of screen
			fmt.Print("\x1B[1;1H")

			// currently 4 metric slots are used: {tx,rx} {packets,bytes}
			for i := 0; i < 4; i++ {
				value, err := metrics.LookupInt(i)
				if err != nil {
					fatalError("LookupInt failed: %v", err)
				}
				if value > 0 {
					fmt.Printf("% -20s: %d\n", getMetricName(i), value)
				}
			}
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

func getMetricName(index int) string {
	unit := "packets"
	direction := "rx"

	if (index & HASH_FLAG_UNIT_BYTES) > 0 {
		unit = "bytes"
	}

	if (index & HASH_FLAG_DIR_EGRESS) > 0 {
		direction = "tx"
	}

	return fmt.Sprintf("[idx %d] %s %s", index, direction, unit)
}
