// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

package goebpf

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
)

func TestRingBuffer(t *testing.T) {
	// Create golang array with test data
	buffer := make([]byte, 8)
	for i := 0; i < len(buffer); i++ {
		buffer[i] = byte(i)
	}

	// Create ring buffer based on filled array
	rb := ringBufferFromArray(buffer)

	// Read 2 bytes
	assert.Equal(t, []byte{0, 1}, rb.Read(2))
	assert.Equal(t, 2, rb.tail)

	// Read 6 bytes (no rollover, right at the edge)
	assert.Equal(t, []byte{2, 3, 4, 5, 6, 7}, rb.Read(6))
	assert.Equal(t, 8, rb.tail)

	// Read entire 8 bytes
	assert.Equal(t, []byte{0, 1, 2, 3, 4, 5, 6, 7}, rb.Read(8))
	assert.Equal(t, 16, rb.tail)

	// Read with rollover (1st read 6 bytes, then 8)
	assert.Equal(t, []byte{0, 1, 2, 3, 4, 5}, rb.Read(6))
	assert.Equal(t, 22, rb.tail)
	assert.Equal(t, []byte{6, 7, 0, 1, 2, 3, 4, 5}, rb.Read(8))
	assert.Equal(t, 30, rb.tail)
}

// Helper to construct ringBuffer from go array
func ringBufferFromArray(array []byte) *mmapRingBuffer {
	ptr := unsafe.Pointer(&array[0])
	size := len(array)

	return &mmapRingBuffer{
		ptr:   ptr,
		start: ptr,
		size:  size,
		end:   uintptr(ptr) + uintptr(size),
	}
}
