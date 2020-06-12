// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

package goebpf_mock

import (
	"github.com/dropbox/goebpf"
)

// MockProgram is mock implementation for eBPF program
type MockProgram struct {
	Attached bool
	Fd       int
	License  string
	Name     string
	Section  string
	Size     int
	ProgType goebpf.ProgramType
}

// NewMockProgram creates new mock program of tp type.
func NewMockProgram(name string, tp goebpf.ProgramType) *MockProgram {
	return &MockProgram{
		Name:     name,
		ProgType: tp,
	}
}

// Load does nothing, only to implement Program interface
func (m *MockProgram) Load() error {
	m.Fd = 1
	return nil
}

// Close does nothing, only to implement Program interface
func (m *MockProgram) Close() error {
	m.Fd = 0
	return nil
}

// Attach does nothing, only to implement Program interface
func (m *MockProgram) Attach(meta interface{}) error {
	m.Attached = true
	return nil
}

// Detach does nothing, only to implement Program interface
func (m *MockProgram) Detach() error {
	m.Attached = false
	return nil
}

// Pin does nothing, just returns nil
func (m *MockProgram) Pin(path string) error {
	return nil
}

// GetFd returns mock program fd
func (m *MockProgram) GetFd() int {
	return m.Fd
}

// GetType returns program type
func (m *MockProgram) GetType() goebpf.ProgramType {
	return m.ProgType
}

// GetLicense return program's license
func (m *MockProgram) GetLicense() string {
	return m.License
}

// GetName return program name
func (m *MockProgram) GetName() string {
	return m.Name
}

// GetSection returns the section name used by the program
func (m *MockProgram) GetSection() string {
	return m.Section
}

// GetSize returns program size set by user
func (m *MockProgram) GetSize() int {
	return m.Size
}
