// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

package goebpf

/*
#include <stdint.h>
#include <poll.h>
#include <string.h>

#ifdef __linux__
#include <linux/perf_event.h>
#else
// mocks for Mac
struct perf_event_mmap_page {
    int data_offset, data_size, data_head, data_tail;
};
#endif

static void *shmem_get_ptr(void *shmem)
{
    struct perf_event_mmap_page *header = shmem;
    return shmem + header->data_offset;
}

static uint64_t shmem_get_size(void *shmem)
{
    struct perf_event_mmap_page *header = shmem;
    return header->data_size;
}

static uint64_t shmem_get_head(void *shmem)
{
    volatile struct perf_event_mmap_page *header = shmem;
    uint64_t head = header->data_head;
    asm volatile("" ::: "memory");  // smp_rmb()

    return head;
}

static uint64_t shmem_get_tail(void *shmem)
{
    volatile struct perf_event_mmap_page *header = shmem;
    return header->data_tail;
}

// Helper to update ring buffer's tail with Memory Barrier
static void shmem_set_tail(void *shmem, uint64_t tail)
{
    volatile struct perf_event_mmap_page *header = shmem;

    __sync_synchronize(); // smp_mb()
    header->data_tail = tail;
}

static void shmem_memcpy(void *shmem, void *buffer, size_t size)
{
    memcpy(buffer, shmem, size);
}

*/
import "C"

import (
	"unsafe"
)

type mmapRingBuffer struct {
	ptr   unsafe.Pointer
	start unsafe.Pointer
	end   uintptr
	size  int

	head int
	tail int
}

// NewMmapRingBuffer creates mmapRingBuffer instance from
// pre-created mmap memory pointer ptr
func NewMmapRingBuffer(ptr unsafe.Pointer) *mmapRingBuffer {
	start := C.shmem_get_ptr(ptr)
	size := int(C.shmem_get_size(ptr))

	res := &mmapRingBuffer{
		ptr:   ptr,
		start: start,
		size:  size,
		end:   uintptr(start) + uintptr(size),
		tail:  int(C.shmem_get_tail(ptr)),
	}

	return res
}

// Read copies "size" bytes from mmaped memory and returns it as go slice
func (b *mmapRingBuffer) Read(size int) []byte {
	if size > b.size {
		size = b.size
	}

	res := make([]byte, size)
	tailPtr := unsafe.Pointer(uintptr(b.start) + uintptr(b.tail%b.size))

	if uintptr(tailPtr)+uintptr(size) > b.end {
		// Requested size requires buffer rollover
		// [------------------------T-]
		// e.g. requested 3 bytes, but current tail is just 2 bytes away from
		// the buffer end.
		// So read 2 bytes and 1 byte from the beginning
		consumed := int(b.end - uintptr(tailPtr))
		C.shmem_memcpy(
			tailPtr,
			unsafe.Pointer(&res[0]),
			C.size_t(consumed),
		)
		C.shmem_memcpy(
			b.start,
			unsafe.Pointer(&res[consumed]),
			C.size_t(size-consumed),
		)
	} else {
		C.shmem_memcpy(
			tailPtr,
			unsafe.Pointer(&res[0]),
			C.size_t(size),
		)
	}

	// Advance tail
	b.tail += size

	return res
}

// Helper to update tail in shmem metadata page
func (b *mmapRingBuffer) UpdateTail() {
	C.shmem_set_tail(
		b.ptr,
		C.uint64_t(b.tail),
	)
}

func (b *mmapRingBuffer) DataAvailable() bool {
	b.head = int(C.shmem_get_head(b.ptr))

	return b.head != b.tail
}
