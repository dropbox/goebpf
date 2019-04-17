// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

package goebpf

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMapFromElf(t *testing.T) {
	payload1 := []byte{
		1, 0, 0, 0, // map type hash
		0xa, 0, 0, 0, // key size is 10
		0, 0x10, 0, 0, // value size is 4096
		0, 0, 0x1, 0, // max items is 65536
		0, 0, 0, 0, // flags
		0, 0, 0, 0, // padding
		// next fields are not used by newMapFromElfSection
		0, 0, 0, 0, 0, 0, 0, 0, // inner map ptr
		0, 0, 0, 0, 0, 0, 0, 0, // persistent path
	}

	m, err := newMapFromElfSection(payload1)
	assert.NoError(t, err)
	assert.Equal(t, MapTypeHash, m.Type)
	assert.Equal(t, 10, m.KeySize)
	assert.Equal(t, 4096, m.ValueSize)
	assert.Equal(t, 65536, m.MaxEntries)

	// Negative
	m, err = newMapFromElfSection([]byte("123"))
	assert.Error(t, err)
	assert.Nil(t, m)
}

func TestMapCloneTemplate(t *testing.T) {
	m := &EbpfMap{
		fd:           10,
		Name:         "map1",
		Type:         MapTypeHash,
		KeySize:      4,
		ValueSize:    4,
		MaxEntries:   100,
		InnerMapName: "inner",
		InnerMapFd:   5,
	}

	cloned := m.CloneTemplate()
	// Ensure that fd hasn't copied
	assert.Equal(t, 0, cloned.GetFd())
	// Compare the rest
	cloned.(*EbpfMap).fd = 10
	assert.Equal(t, m, cloned)
}
