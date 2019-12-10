// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

package goebpf_mock

import (
	"testing"

	"github.com/dropbox/goebpf"
)

// Just to ensure that MockProgram implements goebpf.Program interface
func TestMockProgram(t *testing.T) {
	mockBpf := NewMockSystem()
	mockBpf.Programs["test"] = NewMockProgram("test", goebpf.ProgramTypeXdp)
}
