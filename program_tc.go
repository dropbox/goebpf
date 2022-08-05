// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

package goebpf

import (
	"errors"
	"fmt"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// TC eBPF program (implements Program interface)
type tcProgram struct {
	BaseProgram
	progType  TcProgramType
	link      netlink.Link
	direction TcFlowDirection
	handle    uint32
}

// TcAttachParams is attachment parameters dictating where and how the eBPF
// program is attached. The current behavior is to attach to the "egress"
// and "ingress" pseudo-qdiscs created by clsact.
type TcAttachParams struct {
	// Interface is the name of the network interface to which the program should
	// be attached, i.e. "eth0".
	Interface string

	// Direction is either TcDirectionIngress or TcDirectionEgress.
	Direction TcFlowDirection

	// DirectAction indicates to the linux tc stack whether the eBPF program gets
	// to choose what happens to the packet through its return value. If false, the
	// packet always continues through the filter chain, which is preferred for
	// programs that only log things (i.e. aren't used for altering or classifying
	// traffic).
	DirectAction bool

	// EntryPoint is the name of the symbol (C function) to load from the eBPF
	// program.
	EntryPoint string

	// ClobberIngress tells this library whether to allow replacement of the
	// ingress qdisc with clsact. This could interfere with an existing tc
	// configuration, so the operator is encouraged to tread with caution if
	// enabling this option.
	//
	// If this option is set to false, the clsact qdisc will be installed if
	// no ingress qdisc is presently installed.
	ClobberIngress bool
}

// TcProgramType selects a way how TC program will be attached
// it can either be BPF_PROG_TYPE_SCHED_CLS or BPF_PROG_TYPE_SCHED_ACT
type TcProgramType int

// TcFlowDirection indicates whether the program goes into the egress or ingress
// side of the clsact pseudo-qdisc. Filters have different parent handles which
// are also determined by the value of the direction property.
type TcFlowDirection int

const (
	// TcProgramTypeCls is the `tc filter` program type
	TcProgramTypeCls TcProgramType = iota
	// TcProgramTypeAct is the `tc action` program type
	// Please note, support for this is currently not implemented
	TcProgramTypeAct

	// HANDLE_INGRESS_QDISC is the handle always used by the ingress or clsact
	// qdisc.
	HANDLE_INGRESS_QDISC uint32 = 0xFFFF0000

	// HANDLE_FILTER_BASE is the lowest handle value that will be used by a
	// filter installed by this library. Ideally this should not conflict with
	// filters that might be installed by another script.
	//
	// It should be possible to install multiple filters, including in the
	// same direction, and run them concurrently.
	HANDLE_FILTER_BASE uint32 = 0x1600
)

const (
	TcDirectionIngress TcFlowDirection = iota
	TcDirectionEgress
)

func (t TcProgramType) String() string {
	switch t {
	case TcProgramTypeCls:
		return "tc_cls"
	case TcProgramTypeAct:
		return "tc_act"
	default:
		return "tc_unknown"
	}
}

func newTcSchedClsProgram(bp BaseProgram) Program {
	bp.programType = ProgramTypeSchedCls
	return &tcProgram{
		BaseProgram: bp,
		progType:    TcProgramTypeCls,
	}
}

func newTcSchedActProgram(bp BaseProgram) Program {
	bp.programType = ProgramTypeSchedAct
	return &tcProgram{
		BaseProgram: bp,
		progType:    TcProgramTypeAct,
	}
}

func (t TcFlowDirection) String() string {
	switch t {
	case TcDirectionIngress:
		return "ingress"
	case TcDirectionEgress:
		return "egress"
	default:
		return "unknown"
	}
}

// Parent() converts a TcFlowDirection() to the parent qdisc handle that must
// be used for a filter.
func (t TcFlowDirection) Parent() uint32 {
	switch t {
	case TcDirectionIngress:
		return netlink.HANDLE_MIN_INGRESS
	case TcDirectionEgress:
		return netlink.HANDLE_MIN_EGRESS
	default:
		panic("invalid state of TcFlowDirection")
	}
}

// Attach() attaches an eBPF program to the clsact ingress or egress filter
// chain. It accepts a pointer to a TcAttachParams struct as an argument.
func (p *tcProgram) Attach(data interface{}) error {
	args, ok := data.(*TcAttachParams)
	if !ok {
		return fmt.Errorf("Failed to cast %T as TcAttachParams", data)
	}

	// Attach() cannot be called twice
	if p.link != nil {
		return fmt.Errorf("we already have a link being tracked, did you attempt to Attach() the same program twice?")
	}

	// Lookup interface
	link, err := netlink.LinkByName(args.Interface)
	if err != nil {
		return fmt.Errorf("failed to lookup interface %q: %v", args.Interface, err)
	}

	// track link and direction
	p.link = link
	p.direction = args.Direction

	switch p.programType {
	case ProgramTypeSchedCls:
		// SCHED_CLS programs get installed as filters.
		// To do this, we need to install a special qdisc at handle ffff: called
		// clsact.
		// See: https://lwn.net/Articles/671458/

		// check if there's already an ingress qdisc installed
		ingressQdisc, err := getIngressQdisc(link)
		if err != nil {
			return fmt.Errorf("failed to check interface %q for ingress qdisc: %v", args.Interface, err)
		}

		if ingressQdisc != nil && ingressQdisc.Type() != "clsact" {
			// if there is a qdisc with handle ffff: and it's not a clsact, require permission
			// to clobber it since this will destroy existing rules.
			if !args.ClobberIngress {
				return fmt.Errorf("Refusing to clobber existing ffff: qdisc of type %q. Set "+
					"args.ClobberIngress to true to allow this.", ingressQdisc.Type())
			}

			// delete the existing ingress qdisc
			if err = netlink.QdiscDel(ingressQdisc); err != nil {
				return fmt.Errorf("while removing ingress qdisc: %v", err)
			}

			// set to nil so the next block installs clsact
			ingressQdisc = nil
		}

		if ingressQdisc == nil {
			// this runs if either (1) there was no ffff: qdisc at all, or (2) there was
			// an ingress qdisc on ffff: and we had permission to clobber it
			if err = installClsActQdisc(link); err != nil {
				return fmt.Errorf("failed to create clsact qdisc on interface %q: %v", args.Interface, err)
			}
		}

		// we are ready to install the filter
		err = p.installFilter(args)
		if err != nil {
			return err
		}

		break

	case ProgramTypeSchedAct:
		// SCHED_ACT programs get installed as actions.
		// Currently unsupported.
		return errors.New("TC_SCHED_ACT program support is not currently implemented.")
	}

	return nil
}

// Detach() removes the running program from the filter chain.
func (p *tcProgram) Detach() error {
	if p.link == nil {
		return fmt.Errorf("can't find link object, did Attach() succeed yet?")
	}

	switch p.programType {
	case ProgramTypeSchedCls:
		err := p.uninstallFilter()
		if err != nil {
			return nil
		}

		// We are done. The clsact qdisc can stay, it's a no-op if there are no filters.
		break
	case ProgramTypeSchedAct:
		return errors.New("TC_SCHED_ACT program support is not currently implemented.")
	}

	p.link = nil
	p.handle = 0

	return nil
}

// Iterate through the list of filters under the parent object as determined by the
// direction property (ingress or egress). Return the first handle greater than or
// equal to HANDLE_FILTER_BASE that isn't used by an existing filter.
func (p *tcProgram) getNextFilterHandle() (uint32, error) {
	if p.link == nil {
		return 0, errors.New("cannot iterate filters, link property is not yet set")
	}

	handle := HANDLE_FILTER_BASE
	handles := make(map[uint32]interface{}, 0)

	parent := p.direction.Parent()

	filters, err := netlink.FilterList(p.link, parent)
	if err != nil {
		return 0, err
	}

	for _, filter := range filters {
		handles[filter.Attrs().Handle] = nil
	}

	for {
		if _, ok := handles[handle]; !ok {
			return handle, nil
		}
		handle += 1
	}
}

// Insert a filter under either the ingress (ffff:fff2) or egress (ffff:fff3)
// side of the clsact pseudo-qdisc. The handle is determined automatically from
// the handles that are available.
func (p *tcProgram) installFilter(args *TcAttachParams) error {
	// will be 0xfffffff2 for ingress or 0xfffffff3 for ingress. See
	// HANDLE_MIN_EGRESS and HANDLE_MIN_INGRESS in:
	//    https://github.com/vishvananda/netlink/blob/main/qdisc.go
	parent := p.direction.Parent()
	// determine the handle to use for the filter
	handle, err := p.getNextFilterHandle()
	if err != nil {
		return fmt.Errorf("while determining next available filter handle for program %q on interface %q: %v",
			args.EntryPoint, args.Interface, err)
	}

	// construct the filter
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: p.link.Attrs().Index,
			Parent:    parent,
			Handle:    handle,
			Protocol:  unix.ETH_P_ALL,
			// FIXME(fuhry@2022-08-04): make tweakable?
			Priority: 1,
		},
		Fd:           p.fd,
		Name:         args.EntryPoint,
		DirectAction: args.DirectAction,
	}

	if err = netlink.FilterAdd(filter); err != nil {
		return fmt.Errorf("while loading egress program %q on fd %d: %v", args.EntryPoint, p.fd, err)
	}

	// track handle for later unload
	p.handle = handle

	return nil
}

// Uninstall the filter we previously added.
func (p *tcProgram) uninstallFilter() error {
	// need link and handle already stashed for this to work
	if p.link == nil || p.handle == 0 {
		return errors.New("link or handle not set, this can't be performed unless the program was successfully installed")
	}

	// list out current filters
	parent := p.direction.Parent()
	filters, err := netlink.FilterList(p.link, parent)
	if err != nil {
		return fmt.Errorf("while listing filters for uninstall: %v", err)
	}

	for _, filter := range filters {
		// TODO(fuhry@2022-08-04) this matches only on the handle, also check type etc.?
		if filter.Attrs().Handle == p.handle {
			err = netlink.FilterDel(filter)
			if err != nil {
				return fmt.Errorf("while deleting filter %x from chain %x: %v", p.handle, parent, err)
			}

			// if this succeeded, clear the state before returning
			p.handle = 0
			p.link = nil
			return nil
		}
	}

	return fmt.Errorf("cannot find filter with handle %x to uninstall", p.handle)
}

// get the ingress or clsact pseudo-qdisc, if there is one.
func getIngressQdisc(link netlink.Link) (netlink.Qdisc, error) {
	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return nil, err
	}

	for _, qdisc := range qdiscs {
		attrs := qdisc.Attrs()
		if attrs.LinkIndex != link.Attrs().Index {
			continue
		}
		if (attrs.Handle&0xFFFF0000) == 0xFFFF0000 && attrs.Parent == 0xFFFFFFF1 {
			return qdisc, nil
		}
	}

	return nil, nil
}

// install the clsact qdisc
func installClsActQdisc(link netlink.Link) error {
	clsActAttrs := netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    HANDLE_INGRESS_QDISC,
		Parent:    netlink.HANDLE_CLSACT,
	}
	clsActQdisc := &netlink.GenericQdisc{
		QdiscAttrs: clsActAttrs,
		QdiscType:  "clsact",
	}

	if err := netlink.QdiscAdd(clsActQdisc); err != nil {
		return fmt.Errorf("while installing clsact qdisc: %v", err)
	}

	return nil

}
