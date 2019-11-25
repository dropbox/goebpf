// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

package goebpf

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseNumOfPossibleCpus(t *testing.T) {
	runs := map[string]int{
		"0":       1,
		"0-0":     1,
		"0-1":     2,
		"0-14":    15,
		"0-1\r\n": 2,
	}

	for str, numExpected := range runs {
		num, err := parseNumOfPossibleCpus(str)
		assert.NoError(t, err)
		assert.Equal(t, numExpected, num)
	}

	// Negative runs
	runsNegative := []string{
		"",
		"1",
		"1-1",
		"1-",
		"-1",
		"\r\n",
	}

	for _, str := range runsNegative {
		num, err := parseNumOfPossibleCpus(str)
		assert.Error(t, err)
		assert.Equal(t, 0, num)
	}
}

// Negative test for closeFd()
func TestCloseFd(t *testing.T) {
	err := closeFd(1111) // Some non-existing fd
	assert.Error(t, err)
	assert.Equal(t, "close() failed: Bad file descriptor", err.Error())
}

func TestNullTerminatedStringToString(t *testing.T) {
	assert.Equal(t, "abc", NullTerminatedStringToString([]byte{'a', 'b', 'c'}))
	assert.Equal(t, "def", NullTerminatedStringToString([]byte{'d', 'e', 'f', 0, 'g'}))
	assert.Equal(t, "", NullTerminatedStringToString([]byte{0, 'h'}))
	assert.Equal(t, "", NullTerminatedStringToString([]byte{0}))
}

func TestKeyValueToBytes(t *testing.T) {
	type run struct {
		val   interface{}
		size  int
		bytes []byte
	}
	// key, key_size, expected
	runs := []run{
		// regular integers
		{0x0, 0, []byte{}},
		{0xff, 1, []byte{0xff}},
		{0xff00, 2, []byte{0, 0xff}},
		{0x7ffefdfc, 4, []byte{0xfc, 0xfd, 0xfe, 0x7f}},
		{0x7fffffff, 4, []byte{0xff, 0xff, 0xff, 0x7f}},
		{0x7fffffffffffffff, 8, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}},
		{0x7f, 1, []byte{0x7f}},
		{0x7f, 2, []byte{0x7f, 0}},
		{0x7f, 4, []byte{0x7f, 0, 0, 0}},
		{0x7f, 8, []byte{0x7f, 0, 0, 0, 0, 0, 0, 0}},
		// negative regular integers
		{-1, 8, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
		{-100, 8, []byte{0x9c, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
		// fixed size integers
		{uint8(0), 1, []byte{0}},
		{uint8(1), 2, []byte{1, 0}},
		{uint8(0x7f), 4, []byte{0x7f, 0, 0, 0}},
		{uint8(0xff), 8, []byte{0xff, 0, 0, 0, 0, 0, 0, 0}},

		{uint16(0), 2, []byte{0, 0}},
		{uint16(0xff), 4, []byte{0xff, 0, 0, 0}},
		{uint16(0xffff), 8, []byte{0xff, 0xff, 0, 0, 0, 0, 0, 0}},

		{uint32(0x0), 4, []byte{0x0, 0, 0, 0}},
		{uint32(0xff), 4, []byte{0xff, 0, 0, 0}},
		{uint32(0xffff), 4, []byte{0xff, 0xff, 0, 0}},
		{uint32(0xffffff), 4, []byte{0xff, 0xff, 0xff, 0}},
		{uint32(0xffffffff), 4, []byte{0xff, 0xff, 0xff, 0xff}},
		{uint32(0xffffffff), 8, []byte{0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0}},

		{uint64(0), 8, []byte{0, 0, 0, 0, 0, 0, 0, 0}},
		{uint64(0xffffffff), 8, []byte{0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0}},
		{uint64(0xffffffffffffffff), 8, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},

		// strings
		{"", 0, []byte{}},
		{"", 1, []byte{0}},
		{"a", 1, []byte{'a'}},
		{"b", 4, []byte{'b', 0, 0, 0}},
		{"bc", 4, []byte{'b', 'c', 0, 0}},
		{"aaaa", 4, []byte{'a', 'a', 'a', 'a'}},

		// byte array
		{[]byte{}, 0, []byte{}},
		{[]byte{}, 1, []byte{0}},
		{[]byte{'a'}, 1, []byte{'a'}},
		{[]byte{'b', 0, 0, 0}, 4, []byte{'b', 0, 0, 0}},

		// CreateLPMtrieKey, IPv4
		{CreateLPMtrieKey("192.168.1.0/24"), 8, []byte{0x18, 0x0, 0x0, 0x0, 0xc0, 0xa8, 0x01, 0x0}},
		{CreateLPMtrieKey("192.168.1.55/24"), 8, []byte{0x18, 0x0, 0x0, 0x0, 0xc0, 0xa8, 0x01, 0x0}},
		{CreateLPMtrieKey("192.168.1.1"), 8, []byte{0x20, 0x0, 0x0, 0x0, 0xc0, 0xa8, 0x01, 0x01}},
		{CreateLPMtrieKey("0.0.0.0/0"), 8, []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}},

		// CreateLPMtrieKey, IPv6
		{CreateLPMtrieKey("::/0"), 20, []byte{0x00, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
			0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}},
		{CreateLPMtrieKey("::1/64"), 20, []byte{0x40, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
			0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}},
		{CreateLPMtrieKey("FE80::8329"), 20, []byte{0x80, 0x0, 0x0, 0x0, 0xFE, 0x80, 0x00, 0x00, 0x0,
			0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x83, 0x29}},
	}

	for _, r := range runs {
		res, err := KeyValueToBytes(r.val, r.size)
		assert.NoError(t, err)
		assert.Equal(t, r.bytes, res)
	}
}

func TestKeyValueToBytesNegative(t *testing.T) {
	type run struct {
		val  interface{}
		size int
	}
	runs := []run{
		// regular integers
		{0x1ff, 1},        // 0x1ff requires 2 bytes of storage
		{0x10ffff, 2},     // at least 4 bytes
		{0x10ffffffff, 4}, // at least 5 bytes
		{-1, 4},           // negative integer requires 8 bytes
		// typed integers
		{uint8(0), 0},
		{uint16(1), 1},
		{uint32(1), 3},
		{uint64(1), 7},
		// strings (too long)
		{"1", 0},
		{"1dasdasdsa", 3},
		// bytes (doesn't fit)
		{[]byte{'a'}, 0},
		{[]byte{'a', 0, 1, 2, 3}, 3},
	}

	for _, r := range runs {
		_, err := KeyValueToBytes(r.val, r.size)
		assert.Error(t, err)
	}
}

func TestParseFlexibleInteger(t *testing.T) {
	type run struct {
		rawValue []byte
		expected uint64
	}

	// Reversed test data from TestKeyValueToBytes()
	runs := []run{
		{[]byte{0xff}, 0xff},
		{[]byte{0, 0xff}, 0xff00},
		{[]byte{0xe8, 0x3}, 1000},
		{[]byte{0xfc, 0xfd, 0xfe, 0x7f}, 0x7ffefdfc},
		{[]byte{0xff, 0xff, 0xff, 0x7f}, 0x7fffffff},
		{[]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}, 0x7fffffffffffffff},
		{[]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, 0xffffffffffffffff},
		{[]byte{0x7f, 0, 0, 0}, 0x7f},
		{[]byte{0x7f, 0, 0, 0, 0, 0, 0, 0}, 0x7f},
	}

	for _, r := range runs {
		val := ParseFlexibleIntegerLittleEndian(r.rawValue)
		assert.Equal(t, r.expected, val)
	}
}

func TestParseFlexibleMultiInteger(t *testing.T) {
	type run struct {
		valueSize int
		rawValue  []byte
		expected  uint64
	}

	runs := []run{
		// uint8
		{1, []byte{255}, 255},
		{1, []byte{255, 1}, 255 + 1},
		{1, []byte{255, 1, 2}, 255 + 1 + 2},
		// uint16
		{2, []byte{0x01, 0x0}, 1},
		{2, []byte{0xe8, 0x3}, 1000},
		{2, []byte{0xe8, 0x3, 0x1, 0x0}, 1000 + 1},
		// uint32
		{4, []byte{0x01, 0x0, 0x0, 0x0}, 1},
		{4, []byte{0xA0, 0x86, 0x01, 0x0}, 100000},
		{4, []byte{0xA0, 0x86, 0x01, 0x0, 0x01, 0x0, 0x0, 0x0}, 100000 + 1},
		// uint64
		{8, []byte{0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0}, 0x100000000},
		{8, []byte{0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x100000000 + 1},
	}

	for _, r := range runs {
		m := &EbpfMap{
			Type:          MapTypePerCPUArray,
			ValueSize:     r.valueSize,
			valueRealSize: len(r.rawValue),
		}
		val := m.parseFlexibleMultiInteger(r.rawValue)
		assert.Equal(t, r.expected, val)
	}
}
