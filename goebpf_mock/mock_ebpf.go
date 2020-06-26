// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

package goebpf_mock

import (
	"io"

	"github.com/dropbox/goebpf"
)

// MockSystem is mock implementation of eBPF system
type MockSystem struct {
	Programs map[string]goebpf.Program
	Maps     map[string]goebpf.Map

	// ErrorLoadElf specifies return value for LoadElf() method.
	ErrorLoadElf error
}

// NewMockSystem creates mocked eBPF system with:
// - empty program map
// - all linked mock maps
func NewMockSystem() *MockSystem {
	return &MockSystem{
		Programs: make(map[string]goebpf.Program),
		Maps:     MockMaps,
	}
}

// LoadElf does nothing, just a mock for original LoadElf
func (m *MockSystem) LoadElf(path string) error {
	return m.ErrorLoadElf
}

// Load does nothing, just a mock for original Load
func (m *MockSystem) Load(r io.ReaderAt) error {
	return m.ErrorLoadElf
}

// GetMaps returns all linked eBPF maps
func (m *MockSystem) GetMaps() map[string]goebpf.Map {
	return m.Maps
}

// GetPrograms returns map of added eBPF programs
func (m *MockSystem) GetPrograms() map[string]goebpf.Program {
	return m.Programs
}

// GetMapByName returns eBPF map by name or nil if not found
func (m *MockSystem) GetMapByName(name string) goebpf.Map {
	if result, ok := m.Maps[name]; ok {
		return result
	}
	return nil
}

// GetProgramByName returns eBPF program by name or nil if not found
func (m *MockSystem) GetProgramByName(name string) goebpf.Program {
	if result, ok := m.Programs[name]; ok {
		return result
	}
	return nil
}
