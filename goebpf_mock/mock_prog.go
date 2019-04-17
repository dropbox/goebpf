// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

package goebpf_mock

import (
	"github.com/dropbox/goebpf"
)

// Mock BPF program implementation
type MockProgram struct {
	Attached bool
	Fd       int
	License  string
	Name     string
	Size     int
	ProgType goebpf.ProgramType
}

func NewMockProgram(name string, tp goebpf.ProgramType) *MockProgram {
	return &MockProgram{
		Name:     name,
		ProgType: tp,
	}
}

func (m *MockProgram) Load() error {
	m.Fd = 1
	return nil
}

func (m *MockProgram) Close() error {
	m.Fd = 0
	return nil
}

func (m *MockProgram) Attach(meta string) error {
	m.Attached = true
	return nil
}

func (m *MockProgram) Detach() error {
	m.Attached = false
	return nil
}

func (m *MockProgram) GetFd() int {
	return m.Fd
}

func (m *MockProgram) GetType() goebpf.ProgramType {
	return m.ProgType
}

func (prog *MockProgram) GetLicense() string {
	return prog.License
}

func (prog *MockProgram) GetName() string {
	return prog.Name
}

func (prog *MockProgram) GetSize() int {
	return prog.Size
}
