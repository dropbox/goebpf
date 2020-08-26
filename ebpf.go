// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

package goebpf

import "io"

// System defines interface for eBPF system - top level
// interface to interact with eBPF system
type System interface {
	// Read previously compiled eBPF program at the given path
	LoadElf(path string) error
	// Read previously compiled eBPF program from an io.ReaderAt
	Load(reader io.ReaderAt) error
	// Get all defined eBPF maps
	GetMaps() map[string]Map
	// Returns Map or nil if not found
	GetMapByName(name string) Map
	// Get all eBPF programs
	GetPrograms() map[string]Program
	// Returns Program or nil if not found
	GetProgramByName(name string) Program
}

// Program defines eBPF program interface
type Program interface {
	// Load program into Linux kernel
	Load() error
	// Pin (save, share) program into given location.
	// Location must be mounted as bpffs (mount bpffs -t bpffs /some/location)
	Pin(path string) error
	// Unload program from kernel
	Close() error
	// Attach program to something - depends on program type.
	// - XDP: Attach to network interface (data - iface name, or XdpAttachParams)
	// - SocketFilter: Attach to socket (data - socket fd)
	Attach(data interface{}) error
	// Detach previously attached program
	Detach() error
	// Returns program name as it defined in C code
	GetName() string
	// Returns section name for the program
	GetSection() string
	// Returns program file descriptor (given by kernel)
	GetFd() int
	// Returns size of program in bytes
	GetSize() int
	// Returns program's license
	GetLicense() string
	// Returns program type
	GetType() ProgramType
}

// Map defines interface to interact with eBPF maps
type Map interface {
	Create() error
	GetFd() int
	GetName() string
	GetType() MapType
	Close() error
	// Makes a copy of map definition. This will NOT create map, just copies definition, "template".
	// Useful for array/map of maps use case
	CloneTemplate() Map
	// Generic lookup. Accepts any type which will be
	// converted to []byte eventually, returns bytes
	Lookup(interface{}) ([]byte, error)
	// The same, but does casting of return value to int / uint64
	LookupInt(interface{}) (int, error)
	LookupUint64(interface{}) (uint64, error)
	// The same, but does casting of return value to string
	LookupString(interface{}) (string, error)
	Insert(interface{}, interface{}) error
	Update(interface{}, interface{}) error
	Upsert(interface{}, interface{}) error
	Delete(interface{}) error
	// Implementation of bpf_map_get_next_key
	GetNextKey(interface{}) ([]byte, error)
	GetNextKeyString(interface{}) (string, error)
	GetNextKeyInt(interface{}) (int, error)
	GetNextKeyUint64(interface{}) (uint64, error)
}

const (
	// Maximum buffer size for kernel's eBPF verifier error log messages
	logBufferSize = (256 * 1024)
)

// System implementation
type ebpfSystem struct {
	Programs map[string]Program // eBPF programs by name
	Maps     map[string]Map     // eBPF maps defined by Progs by name
}

// NewDefaultEbpfSystem creates default eBPF system
func NewDefaultEbpfSystem() System {
	return &ebpfSystem{
		Programs: make(map[string]Program),
		Maps:     make(map[string]Map),
	}
}

// GetMaps returns all maps found in .elf file
func (s *ebpfSystem) GetMaps() map[string]Map {
	return s.Maps
}

// GetPrograms returns all eBPF programs found in .elf file
func (s *ebpfSystem) GetPrograms() map[string]Program {
	return s.Programs
}

// GetMapByName returns eBPF map by given name
func (s *ebpfSystem) GetMapByName(name string) Map {
	if result, ok := s.Maps[name]; ok {
		return result
	}
	return nil
}

// GetProgramByName returns eBPF program by given name
func (s *ebpfSystem) GetProgramByName(name string) Program {
	if result, ok := s.Programs[name]; ok {
		return result
	}
	return nil
}
