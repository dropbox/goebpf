// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

package goebpf

//#include "bpf_helpers.h"
import "C"

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// SocketFilterResult is eBPF program return code enum
type SocketFilterResult int

// SocketFilterAttachType is either SO_ATTACH_BPF or SO_ATTACH_REUSEPORT_EBPF
type SocketFilterAttachType int

const (
	SocketFilterDeny  SocketFilterResult = C.SOCKET_FILTER_DENY
	SocketFilterAllow SocketFilterResult = C.SOCKET_FILTER_ALLOW

	SocketAttachTypeFilter    SocketFilterAttachType = SO_ATTACH_BPF
	SocketAttachTypeReusePort SocketFilterAttachType = SO_ATTACH_REUSEPORT_EBPF

	// Constants from Linux kernel, they dont' present in "golang.org/x/sys/unix"
	SO_ATTACH_BPF            = 50
	SO_ATTACH_REUSEPORT_EBPF = 52
	SO_DETACH_FILTER         = 27
)

// SocketFilterAttachParams is accepted as argument to Program.Attach()
type SocketFilterAttachParams struct {
	// SocketFd is socket file descriptor returned by unix.Socket(...)
	SocketFd int
	// AttachType is one of SocketAttachTypeFilter / SocketAttachTypeReusePort
	// depending on use case
	AttachType SocketFilterAttachType
}

func (t SocketFilterResult) String() string {
	switch t {
	case SocketFilterDeny:
		return "Deny"
	case SocketFilterAllow:
		return "Allow"
	}

	return "UNKNOWN"
}

func (t SocketFilterAttachType) String() string {
	switch t {
	case SocketAttachTypeFilter:
		return "AttachTypeFilter"
	case SocketAttachTypeReusePort:
		return "AttachTypeReusePort"
	}

	return "UNKNOWN"
}

type socketFilterProgram struct {
	BaseProgram

	sockFd int
}

func newSocketFilterProgram(bp BaseProgram) Program {
	bp.programType = ProgramTypeSocketFilter
	return &socketFilterProgram{
		BaseProgram: bp,
	}
}

func (p *socketFilterProgram) Attach(data interface{}) error {
	params, ok := data.(SocketFilterAttachParams)
	if !ok {
		return fmt.Errorf("SocketFilterAttachParams expected, got %T", data)
	}
	p.sockFd = params.SocketFd

	err := unix.SetsockoptInt(p.sockFd, unix.SOL_SOCKET, int(params.AttachType), p.GetFd())
	if err != nil {
		return fmt.Errorf("SetSockOpt with %v failed: %v", params.AttachType, err)
	}

	return nil
}

func (p *socketFilterProgram) Detach() error {
	err := unix.SetsockoptInt(p.sockFd, unix.SOL_SOCKET, SO_DETACH_FILTER, 0)
	if err != nil {
		return fmt.Errorf("SetSockOpt with SO_DETACH_FILTER failed: %v", err)
	}

	return nil
}
