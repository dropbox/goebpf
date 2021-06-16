// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

package goebpf

/*
#include <errno.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>

#include "bpf.h"
#include "bpf_helpers.h"

// Mac has syscall() deprecated and this produces some noise during package
// install. Wrap all syscalls into macro
#ifdef __linux__
#define SYSCALL_BPF(command)		\
	syscall(__NR_bpf, command, &attr, sizeof(attr));
#else
#define SYSCALL_BPF(command)		0
#endif

static int ebpf_obj_pin(__u32 fd, const char *pathname,
		void *log_buf, size_t log_size)
{
	union bpf_attr attr = {};

	attr.pathname = ptr_to_u64((void *)pathname);
	attr.bpf_fd = fd;

	int res = SYSCALL_BPF(BPF_OBJ_PIN);
	strncpy(log_buf, strerror(errno), log_size);
	return res;
}

static int ebpf_obj_get(const char *pathname,
		void *log_buf, size_t log_size)
{
	union bpf_attr attr = {};

	attr.pathname = ptr_to_u64(pathname);

	int res = SYSCALL_BPF(BPF_OBJ_GET);
	strncpy(log_buf, strerror(errno), log_size);
	return res;
}

static int ebpf_prog_get_fd_by_id(__u32 id,
		void *log_buf, size_t log_size)
{
	union bpf_attr attr = {};
	attr.prog_id = id;

	int res = SYSCALL_BPF(BPF_PROG_GET_FD_BY_ID);
	strncpy(log_buf, strerror(errno), log_size);

	return res;
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

static int ebpf_obj_get_info_maps(__u32 fd, void *map_ids, __u32 maps_num,
		void *log_buf, size_t log_size)
{
	struct bpf_prog_info info = {};
	union bpf_attr attr = {};

	info.nr_map_ids = maps_num;
	info.map_ids = ptr_to_u64(map_ids);

	attr.info.bpf_fd = fd;
	attr.info.info = ptr_to_u64(&info);
	attr.info.info_len = sizeof(info);

	int res = SYSCALL_BPF(BPF_OBJ_GET_INFO_BY_FD);
	strncpy(log_buf, strerror(errno), log_size);

	return res;
}

static int ebpf_close(int fd, void *log_buf, size_t log_size)
{
	int res = close(fd);
	strncpy(log_buf, strerror(errno), log_size);

	return res;
}

// Workaround for MAC
#ifndef CLOCK_BOOTTIME
	#define CLOCK_BOOTTIME 0
#endif

// Returns system's boot timestamp
static __u64 get_system_boot_timestamp()
{
	struct timespec boot_time_ts, real_time_ts;

	clock_gettime(CLOCK_REALTIME, &real_time_ts);
	clock_gettime(CLOCK_BOOTTIME, &boot_time_ts);

	return real_time_ts.tv_sec - boot_time_ts.tv_sec;
}

*/
import "C"

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const (
	errCodeBufferSize = 512
)

// Number of CPUs - in order to work with Per-CPU eBPF maps.
var numPossibleCpus int
var getPossibleCpusOnce sync.Once

// ProgramInfo - information of already loaded eBPF program info
//
// Main use case is to inspect already loaded into kernel programs.
type ProgramInfo struct {
	Name             string
	Tag              string // Program tag (unclear what this for)
	Type             ProgramType
	Id               int // ID - external ID of program (to refer object)
	Fd               int // fd - local process fd to be able to access the object.
	JitedProgramLen  int // Size of program in CPU instructions
	XlatedProgramLen int // Size of program in bytecode
	LoadTime         time.Time
	CreatedByUid     int            // UID of creator
	Maps             map[string]Map // Associated eBPF maps
}

// NullTerminatedStringToString is helper to convert null terminated string to GO string
func NullTerminatedStringToString(val []byte) string {
	// Calculate null terminated string len
	slen := len(val)
	for idx, ch := range val {
		if ch == 0 {
			slen = idx
			break
		}
	}
	return string(val[:slen])
}

// GetProgramInfoByFd queries information about already loaded eBPF program by fd
// (fd belongs to local process, cannot be shared)
func GetProgramInfoByFd(fd int) (*ProgramInfo, error) {
	var logBuf [errCodeBufferSize]byte
	var infoBuf [1024]byte

	// Get program information
	{
		res := C.ebpf_obj_get_info_by_fd(C.__u32(fd),
			unsafe.Pointer(&infoBuf[0]), C.__u32(len(infoBuf)),
			unsafe.Pointer(&logBuf[0]), C.size_t(unsafe.Sizeof(logBuf)))
		if res == -1 {
			return nil, fmt.Errorf("ebpf_obj_get_info_by_fd() failed: %v",
				NullTerminatedStringToString(logBuf[:]))
		}
	}

	// Read program info from buffer
	var rawInfo struct {
		Type                      uint32
		Id                        uint32
		Tag                       [C.BPF_TAG_SIZE]byte
		JitedProgramLen           uint32
		XlatedProgramLen          uint32
		JitedProgramInstructions  uint64
		XlatedProgramInstructions uint64
		LoadTime                  int64 // in ns since system boot
		CreatedByUid              uint32
		MapIdsLen                 uint32
		MapIds                    uint64
		Name                      [C.BPF_OBJ_NAME_LEN]byte
	}
	reader := bytes.NewReader(infoBuf[:])
	if err := binary.Read(reader, binary.LittleEndian, &rawInfo); err != nil {
		return nil, err
	}

	maps := make(map[string]Map)
	if rawInfo.MapIdsLen > 0 {
		// In case of program is using maps - get all map IDs associated with program
		mapsArray := make([]uint32, rawInfo.MapIdsLen)
		res := C.ebpf_obj_get_info_maps(C.__u32(fd),
			unsafe.Pointer(&mapsArray[0]), C.__u32(len(mapsArray)),
			unsafe.Pointer(&logBuf[0]), C.size_t(unsafe.Sizeof(logBuf)))
		if res == -1 {
			return nil, fmt.Errorf("ebpf_obj_get_info_maps() failed: %v",
				NullTerminatedStringToString(logBuf[:]))
		}
		// Create maps from IDs
		for _, id := range mapsArray {
			m, err := NewMapFromExistingMapById(int(id))
			if err != nil {
				return nil, err
			}
			maps[m.Name] = m
		}
	}

	// Calculate program's load date
	systemBootTime := int64(C.get_system_boot_timestamp())
	loadTimestamp := systemBootTime + (rawInfo.LoadTime / 1000000000)

	return &ProgramInfo{
		Name:             NullTerminatedStringToString(rawInfo.Name[:]),
		Tag:              hex.EncodeToString(rawInfo.Tag[:]),
		Type:             ProgramType(rawInfo.Type),
		Id:               int(rawInfo.Id),
		Fd:               fd,
		JitedProgramLen:  int(rawInfo.JitedProgramLen),
		XlatedProgramLen: int(rawInfo.XlatedProgramLen),
		LoadTime:         time.Unix(loadTimestamp, 0),
		CreatedByUid:     int(rawInfo.CreatedByUid),
		Maps:             maps,
	}, nil
}

// GetProgramInfoById queries information about already loaded eBPF
// program by external ID.
func GetProgramInfoById(id int) (*ProgramInfo, error) {
	var logBuf [errCodeBufferSize]byte

	// Resolve object FD from ID
	fd := C.ebpf_prog_get_fd_by_id(C.__u32(id),
		unsafe.Pointer(&logBuf[0]), C.size_t(unsafe.Sizeof(logBuf)))
	if fd == -1 {
		return nil, fmt.Errorf("ebpf_prog_get_fd_by_id() failed: %v",
			NullTerminatedStringToString(logBuf[:]))
	}

	return GetProgramInfoByFd(int(fd))
}

// GetProgramInfoByPath queries information about already loaded eBPF
// program by using its pinned path in the filesystem.
func GetProgramInfoByPath(path string) (*ProgramInfo, error) {
	fd, err := ebpfObjGet(path)
	if err != nil {
		return nil, err
	}
	p, err := GetProgramInfoByFd(fd)
	if err != nil {
		return p, err
	}

	return p, err
}

// Wrapper for ebpf_obj_get() syscall
func ebpfObjGet(path string) (int, error) {
	var logBuf [errCodeBufferSize]byte

	pathStr := C.CString(path)
	defer C.free(unsafe.Pointer(pathStr))
	fd := C.ebpf_obj_get(pathStr,
		unsafe.Pointer(&logBuf[0]), C.size_t(unsafe.Sizeof(logBuf)),
	)
	if fd == -1 {
		return int(fd), fmt.Errorf("ebpf_obj_get() failed: %v",
			NullTerminatedStringToString(logBuf[:]))
	}
	return int(fd), nil
}

// Wrapper for ebpf_obj_pin() syscall
func ebpfObjPin(fd int, path string) error {
	var logBuf [errCodeBufferSize]byte
	pathCStr := C.CString(path)
	defer C.free(unsafe.Pointer(pathCStr))
	if fd == 0 {
		return errors.New("ebpfObjPin: invalid fd")
	}
	if strings.TrimSpace(path) == "" {
		return errors.New("ebpfObjPin: empty path")
	}
	res := int(C.ebpf_obj_pin(
		C.__u32(fd),
		pathCStr,
		unsafe.Pointer(&logBuf[0]),
		C.size_t(unsafe.Sizeof(logBuf)),
	))
	if res == -1 {
		return fmt.Errorf("ebpfObjPin to '%s' failed: %s",
			path, NullTerminatedStringToString(logBuf[:]))
	}

	return nil
}

// Helper to close linux file descriptor
func closeFd(fd int) error {
	var logBuf [errCodeBufferSize]byte

	res := int(C.ebpf_close(
		C.int(fd),
		unsafe.Pointer(&logBuf[0]),
		C.size_t(unsafe.Sizeof(logBuf))))

	if res == -1 {
		return fmt.Errorf("close() failed: %s",
			NullTerminatedStringToString(logBuf[:]))
	}
	return nil
}

// Helper to get number of possible system CPUs from string
func parseNumOfPossibleCpus(data string) (int, error) {
	eInvalid := errors.New("Unable to get # of possible CPUs: invalid file format")
	// VM support: when machine has only one CPU input is "0"
	if strings.TrimSpace(data) == "0" {
		return 1, nil
	}
	// Otherwise input looks like:
	// 0-14
	// where 0 is first possible CPU and 14 is the last
	items := strings.Split(strings.TrimSpace(data), "-")
	if len(items) != 2 {
		return 0, eInvalid
	}
	first, err := strconv.Atoi(items[0])
	if err != nil || first != 0 {
		return 0, eInvalid
	}
	second, err := strconv.Atoi(items[1])
	if err != nil {
		return 0, eInvalid
	}

	return second + 1, nil
}

// GetNumOfPossibleCpus returns number of CPU available to eBPF program
// NOTE: this is not the same as runtime.NumCPU()
func GetNumOfPossibleCpus() (int, error) {
	// Idea taken from
	// https://elixir.bootlin.com/linux/latest/source/tools/testing/selftests/bpf/bpf_util.h#L10
	// P.S. runtime.NumCPU() cannot be used since it returns number of logical CPUs
	var err error

	getPossibleCpusOnce.Do(func() {
		var data []byte
		data, err = ioutil.ReadFile("/sys/devices/system/cpu/possible")
		if err == nil {
			numPossibleCpus, err = parseNumOfPossibleCpus(string(data))
		}
	})

	return numPossibleCpus, err
}

// ParseFlexibleIntegerLittleEndian converts flexible amount of bytes
// into little endian integer, e.g.:
// {1} -> 1
// {0xe8, 0x3} -> 10000
func ParseFlexibleIntegerLittleEndian(rawVal []byte) uint64 {
	var result uint64
	for idx, val := range rawVal {
		result |= uint64(val) << uint(idx*8)
	}
	return result
}

// KeyValueToBytes coverts interface representation of key/value into bytes
func KeyValueToBytes(ival interface{}, size int) ([]byte, error) {
	overflow := fmt.Errorf("Key/Value is too long (must be at most %d)", size)

	var res = make([]byte, size)

	switch val := ival.(type) {
	case int:
		// Flexible integer, little endian
		remainder := uint64(val)
		for idx := 0; remainder > 0; idx++ {
			if idx == size {
				return nil, overflow
			}
			res[idx] = byte(remainder & 0xff)
			remainder >>= 8
		}
	case uint8:
		if size < 1 {
			return nil, overflow
		}
		res[0] = val
	case uint16:
		if size < 2 {
			return nil, overflow
		}
		binary.LittleEndian.PutUint16(res, val)
	case uint32:
		if size < 4 {
			return nil, overflow
		}
		binary.LittleEndian.PutUint32(res, val)
	case int32:
		if size < 4 {
			return nil, overflow
		}
		binary.LittleEndian.PutUint32(res, uint32(val))
	case uint64:
		if size < 8 {
			return nil, overflow
		}
		binary.LittleEndian.PutUint64(res, val)
	case string:
		if size < len(val) {
			return nil, overflow
		}
		copy(res, val)
	case []byte:
		if size < len(val) {
			return nil, overflow
		}
		copy(res, val)
	case *net.IPNet:
		ones, bits := val.Mask.Size()
		// IP addr size + uint32
		if size < bits/8+4 {
			return nil, overflow
		}
		// Put prefix len
		binary.LittleEndian.PutUint32(res, uint32(ones))
		// Put IP address as is:
		// usually we have to htonl() address (change host to network byte order)
		// however, for eBPF IP addr must be in BIG endian (network byte order)
		copy(res[4:], val.IP)
		return res, nil
	default:
		return nil, fmt.Errorf("Type %T is not supported yet", val)
	}

	return res, nil
}

// KtimeToTime converts kernel time (nanoseconds since boot) to time.Time
func KtimeToTime(ktime uint64) time.Time {
	si := &syscall.Sysinfo_t{}
	syscall.Sysinfo(si)
	boot := time.Now().Add(-time.Duration(si.Uptime) * time.Second)
	return boot.Add(time.Duration(ktime) * time.Nanosecond)
}
