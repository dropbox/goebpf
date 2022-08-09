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

// XdpResult is eBPF program return code enum
type XdpResult int

// XDP program return codes
const (
	XdpAborted  XdpResult = C.XDP_ABORTED
	XdpDrop     XdpResult = C.XDP_DROP
	XdpPass     XdpResult = C.XDP_PASS
	XdpTx       XdpResult = C.XDP_TX
	XdpRedirect XdpResult = C.XDP_REDIRECT
)

// XdpAttachMode selects a way how XDP program will be attached to interface
type XdpAttachMode int

const (
	// XdpAttachModeNone stands for "best effort" - kernel automatically
	// selects best mode (would try Drv first, then fallback to Generic).
	// NOTE: Kernel will not fallback to Generic XDP if NIC driver failed
	//       to install XDP program.
	XdpAttachModeNone XdpAttachMode = 0
	// XdpAttachModeSkb is "generic", kernel mode, less performant comparing to native,
	// but does not requires driver support.
	XdpAttachModeSkb XdpAttachMode = (1 << 1)
	// XdpAttachModeDrv is native, driver mode (support from driver side required)
	XdpAttachModeDrv XdpAttachMode = (1 << 2)
	// XdpAttachModeHw suitable for NICs with hardware XDP support
	XdpAttachModeHw XdpAttachMode = (1 << 3)
)

// XdpAttachParams used to pass parameters to Attach() call.
type XdpAttachParams struct {
	// Interface is string name of interface to attach program to
	Interface string
	// Mode is one of XdpAttachMode.
	Mode XdpAttachMode
}

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

	// Interface name and attach mode
	ifname string
	mode   XdpAttachMode
}

func newXdpProgram(bp BaseProgram) Program {
	bp.programType = ProgramTypeXdp
	return &xdpProgram{
		BaseProgram: bp,
	}
}

// Attach attaches eBPF(XDP) program to network interface.
// There are 2 possible ways to do that:
//
//  1. Pass interface name as parameter, e.g.
//     xdpProgram.Attach("eth0")
//
//  2. Using XdpAttachParams structure:
//     xdpProgram.Attach(
//     &XdpAttachParams{Mode: XdpAttachModeSkb, Interface: "eth0"
//     })
func (p *xdpProgram) Attach(data interface{}) error {
	var ifaceName string
	var attachMode = XdpAttachModeNone // AutoSelect

	switch x := data.(type) {
	case string:
		ifaceName = x
	case *XdpAttachParams:
		ifaceName = x.Interface
		attachMode = x.Mode
	default:
		return fmt.Errorf("%T is not supported for Attach()", data)
	}

	// Lookup interface by given name, we need to extract iface index
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		// Most likely no such interface
		return fmt.Errorf("LinkByName() failed: %v", err)
	}

	// Attach program
	if err := netlink.LinkSetXdpFdWithFlags(link, p.fd, int(attachMode)); err != nil {
		return fmt.Errorf("LinkSetXdpFd() failed: %v", err)
	}

	p.ifname = ifaceName
	p.mode = attachMode

	return nil
}

// Detach detaches program from network interface
// Must be previously attached by Attach() call.
func (p *xdpProgram) Detach() error {
	if p.ifname == "" {
		return errors.New("Program isn't attached")
	}
	// Lookup interface by given name, we need to extract iface index
	link, err := netlink.LinkByName(p.ifname)
	if err != nil {
		// Most likely no such interface
		return fmt.Errorf("LinkByName() failed: %v", err)
	}

	// Setting eBPF program with FD -1 actually removes it from interface
	if err := netlink.LinkSetXdpFdWithFlags(link, -1, int(p.mode)); err != nil {
		return fmt.Errorf("LinkSetXdpFd() failed: %v", err)
	}
	p.ifname = ""

	return nil
}
