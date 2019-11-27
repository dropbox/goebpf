// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

package goebpf

/*
#include <sys/mman.h>
#include <stdint.h>
#include <unistd.h>
#include <linux/perf_event.h>
#include <syscall.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <errno.h>
#include <string.h>


#define PERF_EVENT_HEADER_SIZE      (sizeof(struct perf_event_header))


// Opens perf event on given CPU (>=0).
// Returns pmu_fd (processor monitoring unit fd)
static int perf_event_open(int cpu_id, void *error_buf, size_t error_size)
{
    struct perf_event_attr attr = {
        .sample_type    = PERF_SAMPLE_RAW,
        .type           = PERF_TYPE_SOFTWARE,
        .config         = PERF_COUNT_SW_BPF_OUTPUT,
    };

    // Open perf events for given CPU
    int pmu_fd = syscall(__NR_perf_event_open, &attr, -1, cpu_id, -1, 0);
    if (pmu_fd <= 0) {
        strncpy(error_buf, strerror(errno), error_size);
    }

    return pmu_fd;
}

// Enables perf events on pmu_fd create by perf_event_open()
static int perf_event_enable(int pmu_fd, void *error_buf, size_t error_size)
{
    int res = ioctl(pmu_fd, PERF_EVENT_IOC_ENABLE, 0);
    if (res < 0) {
        strncpy(error_buf, strerror(errno), error_size);
    }

    return res;
}

// Makes shared memory between kernel and user spaces (mmap)
// returns pointer to shared memory
static void *perf_event_mmap(int perf_map_fd, size_t size, void *error_buf, size_t error_size)
{
    void *buf = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, perf_map_fd, 0);
    if (buf == MAP_FAILED) {
        strncpy(error_buf, strerror(errno), error_size);
        return NULL;
    }

    return buf;
}

static int perf_event_poll(int pmu_fd)
{
    struct pollfd poll_fds = { .fd = pmu_fd, .events = POLLIN };


    int res = poll(&poll_fds, 1, 100);
    //printf("pollfd %d, res %d, rev %d\n", pmu_fd, res, poll_fds.revents); fflush(stdout);

    return res;
}

*/
import "C"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"
	"unsafe"
)

// PerfEvent is a way to interact with Linux's PerfEvents for eBPF case.
type PerfEvent struct {
	perfMap        Map
	updatesChannel chan []byte
	stopChannel    chan bool

	pmuFd     C.int
	shMem     unsafe.Pointer
	shMemSize int

	// Statistics
	Success    int
	Losses     int
	UnknowType int
}

// Go definition for C structs from
// http://man7.org/linux/man-pages/man2/perf_event_open.2.html
type perfEventHeader struct {
	// struct perf_event_header {
	Type uint32 //     __u32   type;
	Misc uint16 //     __u16   misc;
	Size uint16 //     __u16   size;
	// }
}

type perfEventLost struct {
	// struct perf_event_lost {
	Id   uint64 //     uint64_t id;
	Lost uint64 //     uint64_t lost;
	// not added: struct sample_id sample_id;
	// }
}

// NewPerfEvent creates new instance of PerfEvent
// eBPF map "m" must be type of "MapTypePerfEventArray"
func NewPerfEvent(m Map) (*PerfEvent, error) {
	if m.GetType() != MapTypePerfEventArray {
		return nil, fmt.Errorf("Invalid map type '%v'", m.GetType())
	}

	return &PerfEvent{
		perfMap: m,
	}, nil
}

// Start starts Perf Event polling.
// All updates will be sent to returned channel.
func (pe *PerfEvent) Start(keys ...int) (<-chan []byte, error) {
	var errorBuf [errCodeBufferSize]byte

	// create perf event
	pe.pmuFd = C.perf_event_open(
		0,
		unsafe.Pointer(&errorBuf[0]), C.size_t(unsafe.Sizeof(errorBuf)),
	)
	if pe.pmuFd <= 0 {
		return nil, fmt.Errorf("Unable to perf_event_open(): %v",
			NullTerminatedStringToString(errorBuf[:]))
	}

	// Tell eBPF system to use pmu_fd for given keys
	for _, key := range keys {
		err := pe.perfMap.Update(key, int(pe.pmuFd))
		if err != nil {
			return nil, err
		}
	}

	// Enable events
	res := C.perf_event_enable(
		pe.pmuFd,
		unsafe.Pointer(&errorBuf[0]), C.size_t(unsafe.Sizeof(errorBuf)), // error message
	)
	if res < 0 {
		return nil, fmt.Errorf("Unable to perf_event_enable(): %v",
			NullTerminatedStringToString(errorBuf[:]))
	}

	// create shared memory (mmap)
	pe.shMemSize = calculateMmapSize(3000)
	pe.shMem = C.perf_event_mmap(
		pe.pmuFd,
		C.size_t(pe.shMemSize),
		unsafe.Pointer(&errorBuf[0]), C.size_t(unsafe.Sizeof(errorBuf)),
	)
	if pe.shMem == C.NULL {
		return nil, fmt.Errorf("Unable to perf_event_mmap(): %v",
			NullTerminatedStringToString(errorBuf[:]))
	}

	pe.stopChannel = make(chan bool)
	pe.updatesChannel = make(chan []byte)

	go pe.loop()

	return pe.updatesChannel, nil
}

// Stop stops event polling loop
func (pe *PerfEvent) Stop() {
	if pe.stopChannel != nil {
		close(pe.stopChannel)
		pe.stopChannel = nil
	}
}

func (pe *PerfEvent) loop() {
	rb := NewMmapRingBuffer(pe.shMem)

	for {
		// Process all new samples
		for rb.DataAvailable() {
			// Read perfEvent header
			var header perfEventHeader
			reader := bytes.NewReader(
				rb.Read(C.PERF_EVENT_HEADER_SIZE),
			)
			binary.Read(reader, binary.LittleEndian, &header)

			// PerfEvent data
			// header.Size means total size of event: header + data
			data := rb.Read(
				int(header.Size - C.PERF_EVENT_HEADER_SIZE),
			)

			// Process event
			switch header.Type {
			case C.PERF_RECORD_SAMPLE:
				// PerfEvent Sample. It is defined as
				//     struct perf_event_sample {
				//         struct perf_event_header header;
				//         uint32_t data_size;
				//         char data[];
				//     };
				// We've already read header, so only read
				// data size and data itself.
				dataSize := binary.LittleEndian.Uint32(data)
				// Send data into channel (w/o datasize)
				pe.updatesChannel <- data[4 : dataSize+4]

			case C.PERF_RECORD_LOST:
				// This is special record type - contains how many perf events
				// loss due to small buffer of lack in record processing
				var lost perfEventLost
				reader := bytes.NewReader(data)
				binary.Read(reader, binary.LittleEndian, &lost)
				pe.Losses += int(lost.Lost)

			default:
				pe.UnknowType++
			}
		}
		rb.UpdateTail()
		time.Sleep(500 * time.Millisecond)
	}
}

// Helper to calculate memory size for mmap
func calculateMmapSize(size int) int {
	pageSize := int(C.getpagesize())
	pageCnt := size / pageSize

	// Extra page for mmap metadata header
	return (pageCnt + 2) * pageSize
}
