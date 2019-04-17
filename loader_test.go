// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

package goebpf

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBpfInstruction(t *testing.T) {
	exp1 := []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
	exp2 := []byte{0x1, 0xab, 0xdd, 0xcc, 0x04, 0x03, 0x02, 0x01}

	// Test save()
	b := &bpfInstruction{}
	assert.Equal(t, exp1, b.save())
	b.code = 1
	b.srcReg = 0xa
	b.dstReg = 0xb
	b.offset = 0xccdd
	b.imm = 0x01020304
	assert.Equal(t, exp2, b.save())

	// Test load()
	b = &bpfInstruction{}
	b.load(exp2)
	assert.Equal(t, uint8(1), b.code)
	assert.Equal(t, uint8(0xa), b.srcReg)
	assert.Equal(t, uint8(0xb), b.dstReg)
	assert.Equal(t, uint16(0xccdd), b.offset)
	assert.Equal(t, uint32(0x01020304), b.imm)
}
