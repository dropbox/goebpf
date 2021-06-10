// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

package goebpf

import (
	"fmt"
)

// TC eBPF program (implements Program interface)
type tcProgram struct {
	BaseProgram
	progType TcProgramType
}

// TcProgramType selects a way how TC program will be attached
// it can either be BPF_PROG_TYPE_SCHED_CLS or BPF_PROG_TYPE_SCHED_ACT
type TcProgramType int

const (
	// TcProgramTypeCls is the `tc filter program type
	TcProgramTypeCls TcProgramType = iota
	// TcProgramTypeAct is the `tc action`program type
	TcProgramTypeAct
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

func (p *tcProgram) Attach(data interface{}) error {
	return fmt.Errorf("Attach() not implemented for program type %s", p.BaseProgram.GetType())
}

func (p *tcProgram) Detach() error {
	return fmt.Errorf("Detach() not implemented for program type %s", p.BaseProgram.GetType())
}
