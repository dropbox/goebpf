// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

package itest

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dropbox/goebpf"
)

func TestGetNumOfPossibleCpus(t *testing.T) {
	cpus := goebpf.GetNumOfPossibleCpus()
	assert.True(t, cpus > 0)
}
