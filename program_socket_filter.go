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

const (
	SocketFilterDeny  SocketFilterResult = C.SOCKET_FILTER_DENY
	SocketFilterAllow SocketFilterResult = C.SOCKET_FILTER_ALLOW

	SO_ATTACH_BPF    = 50
	SO_DETACH_FILTER = 27
)

func (t SocketFilterResult) String() string {
	switch t {
	case SocketFilterDeny:
		return "Deny"
	case SocketFilterAllow:
		return "Allow"
	}

	return "UNKNOWN"
}

// SocketFilter eBPF program (implements Program interface)
type socketFilterProgram struct {
	BaseProgram

	sockFd int
}

func newSocketFilterProgram(name, license string, bytecode []byte) Program {
	return &socketFilterProgram{
		BaseProgram: BaseProgram{
			name:        name,
			license:     license,
			bytecode:    bytecode,
			programType: ProgramTypeSocketFilter,
		},
	}
}

func (p *socketFilterProgram) Attach(data interface{}) error {
	fd, ok := data.(int)
	if !ok {
		return fmt.Errorf("Socket fd (int) expected, got %T", data)
	}
	p.sockFd = fd

	err := unix.SetsockoptInt(p.sockFd, unix.SOL_SOCKET, SO_ATTACH_BPF, p.GetFd())
	if err != nil {
		return fmt.Errorf("SetSockOpt with SO_ATTACH_BPF failed: %v", err)
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
