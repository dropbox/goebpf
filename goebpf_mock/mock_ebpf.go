// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

package goebpf_mock

import (
	"github.com/dropbox/goebpf"
)

// Mock BPF system implementation
type MockSystem struct {
	Programs map[string]goebpf.Program
	Maps     map[string]goebpf.Map
}

func NewMockSystem() *MockSystem {
	return &MockSystem{
		Programs: make(map[string]goebpf.Program),
		Maps:     MockMaps,
	}
}

func (m *MockSystem) LoadElf(fn string) error {
	return nil
}

func (m *MockSystem) GetMaps() map[string]goebpf.Map {
	return m.Maps
}

func (m *MockSystem) GetPrograms() map[string]goebpf.Program {
	return m.Programs
}

func (s *MockSystem) GetMapByName(name string) goebpf.Map {
	if result, ok := s.Maps[name]; ok {
		return result
	} else {
		return nil
	}
}

func (s *MockSystem) GetProgramByName(name string) goebpf.Program {
	if result, ok := s.Programs[name]; ok {
		return result
	} else {
		return nil
	}
}
