// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

package goebpf

//#include "bpf_helpers.h"
import "C"

import (
	"errors"
	"fmt"

	"github.com/vishvananda/netlink"
)

type XdpResult int

const (
	XdpAborted  XdpResult = C.XDP_ABORTED
	XdpDrop     XdpResult = C.XDP_DROP
	XdpPass     XdpResult = C.XDP_PASS
	XdpTx       XdpResult = C.XDP_TX
	XdpRedirect XdpResult = C.XDP_REDIRECT
)

func (t XdpResult) String() string {
	switch t {
	case XdpAborted:
		return "XDP_ABORTED"
	case XdpDrop:
		return "XDP_DROP"
	case XdpPass:
		return "XDP_PASS"
	case XdpTx:
		return "XDP_TX"
	case XdpRedirect:
		return "XDP_REDIRECT"
	}

	return "UNKNOWN"
}

// XDP eBPF program (implements Program interface)
type xdpProgram struct {
	BaseProgram

	// Name of interface where XDP program attached to.
	ifname string
}

func newXdpProgram(name, license string, bytecode []byte) Program {
	return &xdpProgram{
		BaseProgram: BaseProgram{
			name:        name,
			license:     license,
			bytecode:    bytecode,
			programType: ProgramTypeXdp,
		},
	}
}

func (p *xdpProgram) Attach(ifname string) error {
	// Lookup interface by given name, we need to extract iface index
	iface, err := netlink.LinkByName(ifname)
	if err != nil {
		// Most likely no such interface
		return fmt.Errorf("LinkByName() failed: %v", err)
	}

	err = netlink.LinkSetXdpFd(iface, p.fd)
	if err != nil {
		return fmt.Errorf("LinkSetXdpFd() failed: %v", err)
	}
	p.ifname = ifname

	return nil
}

func (p *xdpProgram) Detach() error {
	if p.ifname == "" {
		return errors.New("Program isn't attached")
	}
	// Lookup interface by given name, we need to extract iface index
	iface, err := netlink.LinkByName(p.ifname)
	if err != nil {
		// Most likely no such interface
		return fmt.Errorf("LinkByName() failed: %v", err)
	}

	// Setting eBPF program with FD -1 actually removes it from interface
	err = netlink.LinkSetXdpFd(iface, -1)
	if err != nil {
		return fmt.Errorf("LinkSetXdpFd() failed: %v", err)
	}
	p.ifname = ""

	return nil
}
