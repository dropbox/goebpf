// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

package goebpf

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const pageSize = 4096

func TestMmapMemorySize(t *testing.T) {
	runs := map[int]int{
		1:            pageSize * 2,
		pageSize / 2: pageSize * 2,
		pageSize - 1: pageSize * 2,
		pageSize:     pageSize * 3,
	}

	for left, right := range runs {
		assert.Equal(t, right, calculateMmapSize(left))
	}
}
