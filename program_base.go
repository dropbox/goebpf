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

// Load eBPF program into kernel
static int ebpf_prog_load(const char *name, __u32 prog_type, const void *insns, __u32 insns_cnt,
	const char *license, __u32 kern_version, void *log_buf, size_t log_size)
{
	union bpf_attr attr = {};

	// Try to load program without trace info - it takes too much memory
	// for verifier to put all trace messages even for correct programs
	// and may cause load error because of log buffer is too small.
	attr.prog_type = prog_type;
	attr.insn_cnt = insns_cnt;
	attr.insns = ptr_to_u64(insns);
	attr.license = ptr_to_u64(license);
	attr.log_buf = ptr_to_u64(NULL);
	attr.log_size = 0;
	attr.log_level = 0;
	attr.kern_version = kern_version;
	// program name
	strncpy((char*)&attr.prog_name, name, BPF_OBJ_NAME_LEN - 1);

	int res = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
	if (res == -1) {
		// Try again with log
		attr.log_buf = ptr_to_u64(log_buf);
		attr.log_size = log_size;
		attr.log_level = 1;
		res = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
	}

	return res;
}

static int ebpf_obj_pin(__u32 fd, const char *pathname,
		void *log_buf, size_t log_size)
{
	union bpf_attr attr = {};

	attr.pathname = ptr_to_u64((void *)pathname);
	attr.bpf_fd = fd;

	int res = syscall(__NR_bpf, BPF_OBJ_PIN, &attr, sizeof(attr));
	strncpy(log_buf, strerror(errno), log_size);
	return res;
}

*/
import "C"
import (
	"errors"
	"fmt"
	"unsafe"
)

// ProgramType is eBPF program types enum
type ProgramType int

// Must be in sync with enum bpf_prog_type from <linux/bpf.h>
const (
	ProgramTypeUnspec ProgramType = iota
	ProgramTypeSocketFilter
	ProgramTypeKprobe
	ProgramTypeSchedCls
	ProgramTypeSchedAct
	ProgramTypeTracepoint
	ProgramTypeXdp
	ProgramTypePerfEvent
	ProgramTypeCgroupSkb
	ProgramTypeCgroupSock
	ProgramTypeLwtIn
	ProgramTypeLwtOut
	ProgramTypeLwtXmit
	ProgramTypeSockOps
)

func (t ProgramType) String() string {
	switch t {
	case ProgramTypeSocketFilter:
		return "SocketFilter"
	case ProgramTypeKprobe:
		return "Kprobe"
	case ProgramTypeSchedCls:
		return "SchedCLS"
	case ProgramTypeSchedAct:
		return "SchedACT"
	case ProgramTypeTracepoint:
		return "Tracepoint"
	case ProgramTypeXdp:
		return "XDP"
	case ProgramTypePerfEvent:
		return "PerfEvent"
	case ProgramTypeCgroupSkb:
		return "CgroupSkb"
	case ProgramTypeCgroupSock:
		return "CgroupSock"
	case ProgramTypeLwtIn:
		return "LWTin"
	case ProgramTypeLwtOut:
		return "LWTout"
	case ProgramTypeLwtXmit:
		return "LWTxmit"
	case ProgramTypeSockOps:
		return "SockOps"
	}

	return "Unknown"
}

// BaseProgram is common shared fields of eBPF programs
type BaseProgram struct {
	fd            int // File Descriptor
	name          string
	programType   ProgramType
	license       string // License
	bytecode      []byte // eBPF instructions (each instruction - 8 bytes)
	kernelVersion int    // Kernel requires version to match running for "kprobe" programs
}

// Load loads program into linux kernel
func (prog *BaseProgram) Load() error {
	// Sanity checks
	if len(prog.name) >= C.BPF_OBJ_NAME_LEN {
		return fmt.Errorf("Program name '%s' is too long", prog.name)
	}

	// Buffer for kernel's verified debug messages
	var logBuf [logBufferSize]byte
	// Program name / license
	name := C.CString(prog.name)
	defer C.free(unsafe.Pointer(name))
	license := C.CString(prog.license)
	defer C.free(unsafe.Pointer(license))

	// Load eBPF program
	res := int(C.ebpf_prog_load(
		name,
		C.__u32(prog.GetType()),
		unsafe.Pointer(&prog.bytecode[0]),
		C.__u32(prog.GetSize())/bpfInstructionLen,
		license,
		C.__u32(prog.kernelVersion),
		unsafe.Pointer(&logBuf[0]),
		C.size_t(unsafe.Sizeof(logBuf))))
	if res == -1 {
		return fmt.Errorf("ebpf_prog_load() failed: %s",
			NullTerminatedStringToString(logBuf[:]))
	}
	prog.fd = res

	return nil
}

// Close unloads program from kernel
func (prog *BaseProgram) Close() error {
	if prog.fd == 0 {
		return errors.New("Already closed / not created")
	}
	err := closeFd(prog.fd)
	if err != nil {
		return err
	}

	prog.fd = 0
	return nil
}

func (prog *BaseProgram) Pin(path string) error {
	var logBuf [errCodeBufferSize]byte
	filenameStr := C.CString(path)
	defer C.free(unsafe.Pointer(filenameStr))

	res := int(C.ebpf_obj_pin(
		C.__u32(prog.fd),
		filenameStr,
		unsafe.Pointer(&logBuf[0]),
		C.size_t(unsafe.Sizeof(logBuf)),
	))
	if res == -1 {
		return fmt.Errorf("ebpf_obj_pin() to '%s' failed: %s",
			path, NullTerminatedStringToString(logBuf[:]))
	}

	return nil
}

// GetName returns program name as defined in C code
func (prog *BaseProgram) GetName() string {
	return prog.name
}

// GetType returns program type
func (prog *BaseProgram) GetType() ProgramType {
	return prog.programType
}

// GetFd returns program's file description
func (prog *BaseProgram) GetFd() int {
	return prog.fd
}

// GetSize returns eBPF bytecode size in bytes
func (prog *BaseProgram) GetSize() int {
	return len(prog.bytecode)
}

// GetLicense returns program's license
func (prog *BaseProgram) GetLicense() string {
	return prog.license
}
