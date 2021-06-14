// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

package goebpf

/*
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>

#include "bpf.h"
#include "bpf_helpers.h"

// Mac has syscall() deprecated and this produces some noise during package install.
// Wrap all syscalls into macro.
#ifdef __linux__
#define SYSCALL_BPF(command)		\
	syscall(__NR_bpf, command, &attr, sizeof(attr));
#else
#define SYSCALL_BPF(command)		0
#endif

// Since eBPF mock package is optional and have definition of "__maps_head" symbol
// it may cause link error, so defining weak symbol here as well
struct __create_map_def maps_head;
__attribute__((weak)) struct __maps_head_def *__maps_head = (struct __maps_head_def*) &maps_head;

static int ebpf_map_create(const char *name, __u32 map_type, __u32 key_size, __u32 value_size,
		__u32 max_entries, __u32 flags, __u32 inner_fd, void *log_buf, size_t log_size)
{
	union bpf_attr attr = {};

	attr.map_type = map_type;
	attr.key_size = key_size;
	attr.value_size = value_size;
	attr.max_entries = max_entries;
	attr.map_flags = flags;
	attr.inner_map_fd = inner_fd;
	strncpy((char*)&attr.map_name, name, BPF_OBJ_NAME_LEN - 1);

	int res = SYSCALL_BPF(BPF_MAP_CREATE);
	strncpy(log_buf, strerror(errno), log_size);
	return res;
}

static int ebpf_map_update_elem(__u32 fd, const void *key, const void *value,
		__u64 flags, void *log_buf, size_t log_size)
{
	union bpf_attr attr = {};

	attr.map_fd = fd;
	attr.key = ptr_to_u64(key);
	attr.value = ptr_to_u64(value);
	attr.flags = flags;

	int res = SYSCALL_BPF(BPF_MAP_UPDATE_ELEM);
	strncpy(log_buf, strerror(errno), log_size);
	return res;
}

static int ebpf_map_lookup_elem(__u32 fd, const void *key, void *value,
		void *log_buf, size_t log_size)
{
	union bpf_attr attr = {};

	attr.map_fd = fd;
	attr.key = ptr_to_u64(key);
	attr.value = ptr_to_u64(value);

	int res = SYSCALL_BPF(BPF_MAP_LOOKUP_ELEM);
	strncpy(log_buf, strerror(errno), log_size);
	return res;
}

static int ebpf_map_delete_elem(__u32 fd, const void *key,
		void *log_buf, size_t log_size)
{
	union bpf_attr attr = {};

	attr.map_fd = fd;
	attr.key = ptr_to_u64(key);

	int res = SYSCALL_BPF(BPF_MAP_DELETE_ELEM);
	strncpy(log_buf, strerror(errno), log_size);
	return res;
}

static int ebpf_map_get_fd_by_id(__u32 id,
		void *log_buf, size_t log_size)
{
	union bpf_attr attr = {};
	attr.map_id = id;

	int fd = SYSCALL_BPF(BPF_MAP_GET_FD_BY_ID);
	strncpy(log_buf, strerror(errno), log_size);

	return fd;
}

static int ebpf_obj_get_info_by_fd(__u32 fd, void *info, __u32 info_len,
		void *log_buf, size_t log_size)
{
	union bpf_attr attr = {};

	attr.info.bpf_fd = fd;
	attr.info.info = ptr_to_u64(info);
	attr.info.info_len = info_len;

	int res = SYSCALL_BPF(BPF_OBJ_GET_INFO_BY_FD);
	strncpy(log_buf, strerror(errno), log_size);

	return res;
}

static int ebpf_map_get_next_key(__u32 fd, const void *key, void *next_key,
		void *log_buf, size_t log_size)
{
	union bpf_attr attr = {};

	attr.map_fd = fd;
	attr.key = ptr_to_u64(key);
	attr.next_key = ptr_to_u64(next_key);

	int res = SYSCALL_BPF(BPF_MAP_GET_NEXT_KEY);
	strncpy(log_buf, strerror(errno), log_size);
	return res;
}

*/
import "C"

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"unsafe"
)

// MapType is eBPF map type enum
type MapType int

// Supported eBPF map types.
const (
	MapTypeHash                MapType = C.BPF_MAP_TYPE_HASH
	MapTypeArray               MapType = C.BPF_MAP_TYPE_ARRAY
	MapTypeProgArray           MapType = C.BPF_MAP_TYPE_PROG_ARRAY
	MapTypePerfEventArray      MapType = C.BPF_MAP_TYPE_PERF_EVENT_ARRAY
	MapTypePerCPUHash          MapType = C.BPF_MAP_TYPE_PERCPU_HASH
	MapTypePerCPUArray         MapType = C.BPF_MAP_TYPE_PERCPU_ARRAY
	MapTypeStackTrace          MapType = C.BPF_MAP_TYPE_STACK_TRACE
	MapTypeCgroupArray         MapType = C.BPF_MAP_TYPE_CGROUP_ARRAY
	MapTypeLRUHash             MapType = C.BPF_MAP_TYPE_LRU_HASH
	MapTypeLRUPerCPUHash       MapType = C.BPF_MAP_TYPE_LRU_PERCPU_HASH
	MapTypeLPMTrie             MapType = C.BPF_MAP_TYPE_LPM_TRIE
	MapTypeArrayOfMaps         MapType = C.BPF_MAP_TYPE_ARRAY_OF_MAPS
	MapTypeHashOfMaps          MapType = C.BPF_MAP_TYPE_HASH_OF_MAPS
	MapTypeDevMap              MapType = C.BPF_MAP_TYPE_DEVMAP
	MapTypeSockMap             MapType = C.BPF_MAP_TYPE_SOCKMAP
	MapTypeCPUMap              MapType = C.BPF_MAP_TYPE_CPUMAP
	MapTypeXSKMap              MapType = C.BPF_MAP_TYPE_XSKMAP
	MapTypeSockHash            MapType = C.BPF_MAP_TYPE_SOCKHASH
	MapTypeCGroupStorage       MapType = C.BPF_MAP_TYPE_CGROUP_STORAGE
	MapTypeReusePortSockArray  MapType = C.BPF_MAP_TYPE_REUSEPORT_SOCKARRAY
	MapTypePerCpuCGroupStorage MapType = C.BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE
	MapTypeQueue               MapType = C.BPF_MAP_TYPE_QUEUE
	MapTypeStack               MapType = C.BPF_MAP_TYPE_STACK
	MapTypeSKStorage           MapType = C.BPF_MAP_TYPE_SK_STORAGE
)

// Optional flags for ebpf_map_create()
const (
	bpfNoPrealloc       = 1
	bpfNoCommonLRU      = 2
	bpfNumaNode         = 4
	bpfReadOnly         = 8
	bpfWriteOnly        = 16
	bpfStackBuildId     = 32
	bpfZeroSeed         = 64
	bpfReadOnlyProgram  = 128
	bpfWriteOnlyProgram = 256
)

// Optional flags for ebpf_map_update_elem()
const (
	bpfAny     = C.BPF_ANY     // create new element or update existing
	bpfNoexist = C.BPF_NOEXIST // create new element if it didn't exist
	bpfExist   = C.BPF_EXIST   // update existing element
	bpfFLock   = C.BPF_F_LOCK  // spin_lock-ed map_lookup/map_update
)

// Returns user friendly name for MapType
func (t MapType) String() string {
	switch t {
	case MapTypeHash:
		return "Hash"
	case MapTypeArray:
		return "Array"
	case MapTypeProgArray:
		return "Array of programs"
	case MapTypePerfEventArray:
		return "Event array"
	case MapTypePerCPUHash:
		return "Per-CPU hash"
	case MapTypePerCPUArray:
		return "Per-CPU array"
	case MapTypeStackTrace:
		return "Stack trace"
	case MapTypeCgroupArray:
		return "Cgroup array"
	case MapTypeLRUHash:
		return "LRU hash"
	case MapTypeLRUPerCPUHash:
		return "LRU per-CPU hash"
	case MapTypeLPMTrie:
		return "Longest prefix match trie"
	case MapTypeArrayOfMaps:
		return "Array of maps"
	case MapTypeHashOfMaps:
		return "Hash of maps"
	case MapTypeDevMap:
		return "Device map"
	case MapTypeSockMap:
		return "Socket map"
	case MapTypeCPUMap:
		return "CPU map"
	case MapTypeXSKMap:
		return "AF_XDP socket map"
	case MapTypeSockHash:
		return "Socket hash"
	case MapTypeCGroupStorage:
		return "CGroup storage"
	case MapTypeReusePortSockArray:
		return "Reuseport socket array"
	case MapTypePerCpuCGroupStorage:
		return "per-CPU CGroup storage"
	case MapTypeQueue:
		return "Queue"
	case MapTypeStack:
		return "Stack"
	case MapTypeSKStorage:
		return "Socket storage"
	}

	return "Unknown"
}

// EbpfMap is structure to define eBPF map
type EbpfMap struct {
	fd int
	// Map name, picked up automatically by loader from ELF section
	Name       string
	Type       MapType
	KeySize    int
	ValueSize  int
	MaxEntries int
	Flags      int
	// Name of eBPF map used as template for all inner maps. Only for array/hash of maps
	InnerMapName string
	InnerMapFd   int
	// Persistent eBPF map use case: contains path to special file in filesystem.
	// WARNING: filesystem must be mounted as BPF
	PersistentPath string

	// In case of Per-CPU maps bpf_lookup call expects buffer equal to valueSize * nCPUs
	// which will be populated with data from all possible CPUs
	valueRealSize int
}

// CreateLPMtrieKey converts string representation of CIDR into net.IPNet
// in order to support special eBPF map type: LPMtrie ("Longest Prefix Match Trie")
// Can be used to match single IPv4/6 address with multiple CIDRs, like
//	m.Insert(CreateLPMtrieKey("192.168.0.0/16"), "value16")
//	m.Insert(CreateLPMtrieKey("192.168.0.0/24"), "value24")
//
//	value, err := m.LookupString(CreateLPMtrieKey("192.168.0.10"))
//
// IP 192.168.0.10 matches both CIDRs, however lookup value will be "value24" since /24 prefix is smaller than /16
func CreateLPMtrieKey(s string) *net.IPNet {
	var ipnet *net.IPNet
	// Check if given address is CIDR
	if strings.Contains(s, "/") {
		_, ipnet, _ = net.ParseCIDR(s)
	} else {
		if strings.Contains(s, ":") {
			// IPv6
			_, ipnet, _ = net.ParseCIDR(s + "/128")
		} else {
			// IPv4
			_, ipnet, _ = net.ParseCIDR(s + "/32")
		}
	}
	return ipnet
}

// Creates map from ELF section definition
// Helper to create BPF map from binary representation stored
// in ELF section, defined in BPF program itself.
// Refer to bpf_helpers.h, struct bpf_map_def
const (
	mapDefinitionSize             = C.BPF_MAP_DEF_SIZE
	mapDefinitionPersistentOffset = C.BPF_MAP_OFFSET_PERSISTENT
	mapDefinitionInnerMapOffset   = C.BPF_MAP_OFFSET_INNER_MAP
)

// Create EbpfMap binary data stored in ELF section
func newMapFromElfSection(data []byte) (*EbpfMap, error) {
	if len(data) < mapDefinitionSize {
		return nil, errors.New("Invalid binary representation of BPF map")
	}

	return &EbpfMap{
		Type:       MapType(binary.LittleEndian.Uint32(data[:4])),
		KeySize:    int(binary.LittleEndian.Uint32(data[4:])),
		ValueSize:  int(binary.LittleEndian.Uint32(data[8:])),
		MaxEntries: int(binary.LittleEndian.Uint32(data[12:])),
		Flags:      int(binary.LittleEndian.Uint32(data[16:])),
	}, nil
}

// NewMapFromExistingMapByFd creates eBPF map from already existing map by fd
// available to current process (i.e. created by it).
// In other words it will work only on maps created by current process.
func NewMapFromExistingMapByFd(fd int) (*EbpfMap, error) {
	var logBuf [errCodeBufferSize]byte
	var infoBuf [1024]byte

	// Get map information
	res := C.ebpf_obj_get_info_by_fd(C.__u32(fd),
		unsafe.Pointer(&infoBuf[0]), C.__u32(len(infoBuf)),
		unsafe.Pointer(&logBuf[0]), C.size_t(unsafe.Sizeof(logBuf)))
	if res == -1 {
		return nil, fmt.Errorf("ebpf_obj_get_info_by_fd() failed: %v",
			NullTerminatedStringToString(logBuf[:]))
	}

	// Read definition
	var rawInfo struct {
		Type       uint32
		Id         uint32
		KeySize    uint32
		ValueSize  uint32
		MaxEntries uint32
		Flags      uint32
		Name       [C.BPF_OBJ_NAME_LEN]byte
	}
	reader := bytes.NewReader(infoBuf[:])
	if err := binary.Read(reader, binary.LittleEndian, &rawInfo); err != nil {
		return nil, err
	}

	m := &EbpfMap{
		fd:         fd,
		Name:       NullTerminatedStringToString(rawInfo.Name[:]),
		Type:       MapType(rawInfo.Type),
		KeySize:    int(rawInfo.KeySize),
		ValueSize:  int(rawInfo.ValueSize),
		MaxEntries: int(rawInfo.MaxEntries),
		Flags:      int(rawInfo.Flags),
	}

	if err := m.setValueRealSize(); err != nil {
		return nil, err
	}

	return m, nil
}

// NewMapFromExistingMapById creates eBPF map from BPF object ID.
// BPF object ID is a kernel mechanism to let non owner process to use BPF objects.
// Common use case - tooling for troubleshoot / inspect existing BPF objects in the kernel.
func NewMapFromExistingMapById(id int) (*EbpfMap, error) {
	var logBuf [errCodeBufferSize]byte

	// Resolve object FD from ID
	fd := C.ebpf_map_get_fd_by_id(C.__u32(id),
		unsafe.Pointer(&logBuf[0]), C.size_t(unsafe.Sizeof(logBuf)))
	if fd == -1 {
		return nil, fmt.Errorf("ebpf_map_get_fd_by_id() failed: %v",
			NullTerminatedStringToString(logBuf[:]))
	}

	return NewMapFromExistingMapByFd(int(fd))
}

// NewMapFromExistingMapMapByPath creates eBPF map from a pinned BPF object path.
// Pinned BPF object is a kernel mechanism to let non owner process to use BPF objects.
// Common use case - tooling for troubleshoot / inspect existing BPF objects in the kernel.
func NewMapFromExistingMapByPath(path string) (*EbpfMap, error) {
	fd, err := ebpfObjGet(path)
	if err != nil {
		return nil, err
	}
	m, err := NewMapFromExistingMapByFd(fd)
	if err != nil {
		return m, err
	}

	m.PersistentPath = path
	return m, err
}

// If map type is Per-CPU based
func (m *EbpfMap) isPerCpu() bool {
	return m.Type == MapTypePerCPUArray ||
		m.Type == MapTypePerCPUHash ||
		m.Type == MapTypeLRUPerCPUHash ||
		m.Type == MapTypePerCpuCGroupStorage
}

// Per-CPU maps require extra space to store values from ALL possible CPUs.
// For access from userspace, each single value is padded so that it's a multiple of 8 bytes.
// See: https://github.com/torvalds/linux/commit/15a07b33814d14ca817887dbea8530728dc0fbe4
func (m *EbpfMap) setValueRealSize() error {
	if m.isPerCpu() {
		numCpus, err := GetNumOfPossibleCpus()
		if err != nil {
			return err
		}
		m.valueRealSize = ((m.ValueSize + 7) / 8) * 8 * numCpus
	} else {
		m.valueRealSize = m.ValueSize
	}
	return nil
}

// Map elements part: lookup, update / delete / etc

// Create creates map in kernel
func (m *EbpfMap) Create() error {
	var logBuf [errCodeBufferSize]byte

	// These special map types always have 4 bytes length value
	if m.Type == MapTypeArrayOfMaps || m.Type == MapTypeHashOfMaps ||
		m.Type == MapTypeProgArray || m.Type == MapTypePerfEventArray {

		m.ValueSize = 4
	}

	// Array's key must always be 4 bytes
	if m.Type == MapTypeArray || m.Type == MapTypePerCPUArray ||
		m.Type == MapTypeArrayOfMaps || m.Type == MapTypeProgArray ||
		m.Type == MapTypePerfEventArray {

		if m.KeySize > 4 {
			return fmt.Errorf("Invalid map '%s' key size(%d), must be 4 bytes", m.Name, m.KeySize)
		}
		// Allow to omit key size
		if m.KeySize == 0 {
			m.KeySize = 4
		}
	}

	// LPM-Trie maps require BPF_F_NO_PREALLOC flag
	if m.Type == MapTypeLPMTrie {
		m.Flags |= bpfNoPrealloc
	}

	// Perform few sanity checks
	if len(m.Name) >= C.BPF_OBJ_NAME_LEN {
		return fmt.Errorf("Map name '%s' is too long", m.Name)
	}
	if m.KeySize < 1 {
		return fmt.Errorf("Invalid map '%s' key size(%d)", m.Name, m.KeySize)
	}
	if m.ValueSize < 1 {
		return fmt.Errorf("Invalid map '%s' value size(%d)", m.Name, m.ValueSize)
	}

	if err := m.setValueRealSize(); err != nil {
		return err
	}

	// Don't re-create map if it has fd assigned (NewMapFromExisting use case)
	if m.fd != 0 {
		return nil
	}

	// Make C string from map name
	name := C.CString(m.Name)
	defer C.free(unsafe.Pointer(name))
	// Map can be defined as either process only or system wide ("object pinning")
	// If PersistentPath is set - it indicates that eBPF program wants to
	// make this map system wide accessible via PersistentPath (it is just filename)
	if m.PersistentPath != "" {
		// Try to locate map in the system on
		// given path (i.e. map has been already created before)
		objFd, _ := ebpfObjGet(m.PersistentPath)
		if objFd != -1 {
			// Successful, retrieved map fd from given location
			m.fd = objFd
			return nil
		}
		// No map at given location present yet, create it!
	}
	newFd := int(C.ebpf_map_create(
		name,
		C.__u32(m.Type),
		C.__u32(m.KeySize),
		C.__u32(m.ValueSize),
		C.__u32(m.MaxEntries),
		C.__u32(m.Flags),
		C.__u32(m.InnerMapFd),
		unsafe.Pointer(&logBuf[0]),
		C.size_t(unsafe.Sizeof(logBuf)),
	))

	if newFd == -1 {
		return fmt.Errorf("ebpf_create_map() failed: %s",
			NullTerminatedStringToString(logBuf[:]))
	}
	m.fd = newFd

	// If eBPF program decides to make this map system wide - pin it to given location
	if m.PersistentPath != "" {
		err := ebpfObjPin(m.fd, m.PersistentPath)
		if err != nil {
			// Destroy just created map
			cerr := m.Close()
			if cerr != nil {
				return fmt.Errorf("%v, also close() failed: %v", err, cerr)
			}
			return err
		}
	}

	return nil
}

// Close destroy eBPF map (removes it from kernel)
func (m *EbpfMap) Close() error {
	if m.fd == 0 {
		return errors.New("Already closed / not created")
	}
	err := closeFd(m.fd)
	if err != nil {
		return err
	}

	m.fd = 0
	return nil
}

// CloneTemplate creates new instance of eBPF map using current map parameters.
// Main use case is work with array/hash of maps:
//
//	// Create new map based on template
//	newItem := templateMap.CloneTemplate()
//	newItem.Create()
//	// Insert item into array of maps
//	superMap.Insert(1, newItem)
func (m *EbpfMap) CloneTemplate() Map {
	res := *m
	res.fd = 0

	return &res
}

// Lookup performs lookup and returns array of bytes
// WARNING: For Per-CPU array/hash map return value will contain
// data from all CPUs, i.e. length = roundUp(valueSize, 8) * nCPU
func (m *EbpfMap) Lookup(ikey interface{}) ([]byte, error) {
	// Convert key into bytes
	key, err := KeyValueToBytes(ikey, int(m.KeySize))
	if err != nil {
		return nil, err
	}

	var val = make([]byte, m.valueRealSize)
	var logBuf [errCodeBufferSize]byte

	res := int(C.ebpf_map_lookup_elem(
		C.__u32(m.fd),
		unsafe.Pointer(&key[0]),
		unsafe.Pointer(&val[0]),
		unsafe.Pointer(&logBuf[0]),
		C.size_t(unsafe.Sizeof(logBuf))))

	if res == -1 {
		return nil, fmt.Errorf("ebpf_map_lookup_elem() failed: %s",
			NullTerminatedStringToString(logBuf[:]))
	}

	return val, nil
}

// LookupString perform lookup and returns GO string from NULL terminated C string
// WARNING: Does NOT work for Per-CPU maps (not an real use case?).
func (m *EbpfMap) LookupString(ikey interface{}) (string, error) {
	if m.isPerCpu() {
		return "", fmt.Errorf("LookupString is not supported for %v", m.Type)
	}
	val, err := m.Lookup(ikey)
	if err != nil {
		return "", err
	}
	return NullTerminatedStringToString(val), nil
}

// Helper to read flexible integer value from bytes
// with support for per-cpu maps (multiple values joined into one buffer)
func (m *EbpfMap) parseFlexibleMultiInteger(rawVal []byte) uint64 {
	// Per-CPU map types have slightly different behavior:
	// lookup returns all values in single call, e.g. assuming for uint32 and 2 CPUs:
	// {0x01, 0x00, 0x00, 0x00, 0x0ff, 0x00, 0x00, 0x00}
	//   ^^^^ CPU0 value ^^^^    ^^^^ CPU1 value^^^^^
	//  = 0x01 + 0xff = 256
	//
	// First value (for all map types)
	val := ParseFlexibleIntegerLittleEndian(rawVal[:m.ValueSize])
	if m.isPerCpu() {
		// Sum up values from all CPUs in case of Per-CPU maps,
		// starting from second item
		for i := m.ValueSize; i < m.valueRealSize; i += m.ValueSize {
			val += ParseFlexibleIntegerLittleEndian(rawVal[i : i+m.ValueSize])
		}
	}
	return val
}

// LookupInt performs lookup and returns integer
// WARNING: For Per-CPU array/hash returns sum of values from all CPUs
func (m *EbpfMap) LookupInt(ikey interface{}) (int, error) {
	val, err := m.LookupUint64(ikey)
	return int(val), err
}

// LookupUint64 performs lookup and returns uint64
// WARNING: For Per-CPU array/hash returns sum of values from all CPUs
func (m *EbpfMap) LookupUint64(ikey interface{}) (uint64, error) {
	if m.ValueSize > 8 {
		return 0, errors.New("Value is too large to fit int")
	}
	rawVal, err := m.Lookup(ikey)
	if err != nil {
		return 0, err
	}
	return m.parseFlexibleMultiInteger(rawVal), nil
}

// Actual implementation for Insert / Update methods
func (m *EbpfMap) updateImpl(ikey interface{}, ivalue interface{}, op int) error {
	// Special maps ArrayOfMaps/ProgArray/PerfEventArray requires BPF_ANY
	// in order to update item for some reason... :(
	if m.Type == MapTypeArrayOfMaps || m.Type == MapTypeProgArray || m.Type == MapTypePerfEventArray {
		op = bpfAny
	}
	// Convert key/value into bytes
	key, err := KeyValueToBytes(ikey, int(m.KeySize))
	if err != nil {
		return err
	}

	val, err := KeyValueToBytes(ivalue, int(m.valueRealSize))
	if err != nil {
		return err
	}

	var logBuf [errCodeBufferSize]byte

	res := int(C.ebpf_map_update_elem(
		C.__u32(m.fd),
		unsafe.Pointer(&key[0]),
		unsafe.Pointer(&val[0]),
		C.__u64(op),
		unsafe.Pointer(&logBuf[0]),
		C.size_t(unsafe.Sizeof(logBuf))))

	if res == -1 {
		return fmt.Errorf("ebpf_map_update_elem() failed: %s",
			NullTerminatedStringToString(logBuf[:]))
	}

	return nil

}

// Insert inserts value into eBPF map at given ikey.
// Supported key/value types are: int, uint8, uint16, uint32, int32, uint64, string, []byte, net.IPNet
func (m *EbpfMap) Insert(ikey interface{}, ivalue interface{}) error {
	return m.updateImpl(ikey, ivalue, bpfNoexist)
}

// Update updates (replaces) element at given ikey.
// Supported ivalue types are: int, uint8, uint16, uint32, int32, uint64, string, []byte, net.IPNet
//
// Element must be inserted before for non array types (map, hash)
func (m *EbpfMap) Update(ikey interface{}, ivalue interface{}) error {
	return m.updateImpl(ikey, ivalue, bpfExist)
}

// Upsert updates (replaces) or inserts element at given ikey.
// Supported ivalue types are: int, uint8, uint16, uint32, int32, uint64, string, []byte, net.IPNet
//
func (m *EbpfMap) Upsert(ikey interface{}, ivalue interface{}) error {
	return m.updateImpl(ikey, ivalue, bpfAny)
}

// Delete deletes element by given ikey.
// Array based types are not supported.
func (m *EbpfMap) Delete(ikey interface{}) error {
	// Convert key into bytes
	key, err := KeyValueToBytes(ikey, int(m.KeySize))
	if err != nil {
		return err
	}

	var logBuf [errCodeBufferSize]byte

	res := int(C.ebpf_map_delete_elem(
		C.__u32(m.fd),
		unsafe.Pointer(&key[0]),
		unsafe.Pointer(&logBuf[0]),
		C.size_t(unsafe.Sizeof(logBuf))))

	if res == -1 {
		return fmt.Errorf("ebpf_map_delete_elem() failed: %s",
			NullTerminatedStringToString(logBuf[:]))
	}

	return nil
}

// GetNextKey looks up next key in the map.
// returns 'next_key' on success, 'err' on failure (or last key in map - no next key available).
func (m *EbpfMap) GetNextKey(ikey interface{}) ([]byte, error) {
	// Convert key into bytes
	key, err := KeyValueToBytes(ikey, int(m.KeySize))
	if err != nil {
		return nil, err
	}

	var nextKey = make([]byte, m.KeySize)
	var logBuf [errCodeBufferSize]byte

	res := int(C.ebpf_map_get_next_key(
		C.__u32(m.fd),
		unsafe.Pointer(&key[0]),
		unsafe.Pointer(&nextKey[0]),
		unsafe.Pointer(&logBuf[0]),
		C.size_t(unsafe.Sizeof(logBuf))))

	if res == -1 {
		return nil, fmt.Errorf("ebpf_map_get_next_key() failed: %s",
			NullTerminatedStringToString(logBuf[:]))
	}

	return nextKey, nil
}

// GetNextKeyString looks up next key in the map and returns it
// as a golang string.
func (m *EbpfMap) GetNextKeyString(ikey interface{}) (string, error) {
	nextKey, err := m.GetNextKey(ikey)
	if err != nil {
		return "", err
	}
	return NullTerminatedStringToString(nextKey), nil
}

// GetNextKeyInt looks up next key in the map and returns it
// as int.
func (m *EbpfMap) GetNextKeyInt(ikey interface{}) (int, error) {
	nextKey, err := m.GetNextKeyUint64(ikey)
	return int(nextKey), err
}

// GetNextKeyUint64 looks up next key in the map and returns it
// as uint64.
func (m *EbpfMap) GetNextKeyUint64(ikey interface{}) (uint64, error) {
	if m.KeySize > 8 {
		return 0, errors.New("Value is too large to fit int")
	}
	nextKey, err := m.GetNextKey(ikey)
	if err != nil {
		return 0, err
	}
	return m.parseFlexibleMultiInteger(nextKey), nil
}

// GetFd returns fd (file descriptor) of eBPF map
func (m *EbpfMap) GetFd() int {
	return m.fd
}

// GetName returns map name
func (m *EbpfMap) GetName() string {
	return m.Name
}

// GetType returns map type
func (m *EbpfMap) GetType() MapType {
	return m.Type
}
