// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

package goebpf_mock

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dropbox/goebpf"
	mock_wrapper "github.com/dropbox/goebpf/goebpf_mock/wrapper"
)

// cgo-test does not support import C code
// workaround is move C stuff into separated package and include it
// only from tests
var _ = mock_wrapper.Dummy

func TestMockMapCloneTemplate(t *testing.T) {
	var dummy int
	m := &MockMap{
		fd:         unsafe.Pointer(&dummy),
		Name:       "mockmap1",
		Type:       goebpf.MapTypeHash,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 100,
	}

	cloned := m.CloneTemplate()
	// Ensure that fd hasn't copied
	assert.Equal(t, 0, cloned.GetFd())
	// Compare the rest
	cloned.(*MockMap).fd = unsafe.Pointer(&dummy)
	assert.Equal(t, m, cloned)
}

func TestMockMapCreateRuntime(t *testing.T) {
	// Dynamically create mockMap
	m := &MockMap{
		Name:       "runtime1",
		Type:       goebpf.MapTypeArray,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 100,
	}
	err := m.Create()
	require.NoError(t, err)

	// Lookup non inserted/updated item
	value, err := m.LookupInt(4)
	assert.NoError(t, err)
	assert.Equal(t, 0, value)
	// Update non existing item
	err = m.Update(5, 100)
	assert.NoError(t, err)
	// Check it
	value, err = m.LookupInt(5)
	assert.NoError(t, err)
	assert.Equal(t, 100, value)

	// Re-create map
	err = m.Destroy()
	assert.NoError(t, err)
	err = m.Create()
	assert.NoError(t, err)
	// Ensure that 5th value defaults to zero instead of 100
	value, err = m.LookupInt(5)
	assert.NoError(t, err)
	assert.Equal(t, 0, value)
}

func TestMockMapArray(t *testing.T) {
	// Destroy / Create
	m := MockMaps["map_array"].(*MockMap)
	err := m.Destroy()
	require.NoError(t, err)
	err = m.Create()
	require.NoError(t, err)

	// Deleting items from array doesn't make sense - they are fixed size
	// Should not raise error
	err = m.Delete(4)
	assert.NoError(t, err)

	// Lookup non existing element - default value expected
	value, err := m.LookupInt(4)
	assert.NoError(t, err)
	assert.Equal(t, 0, value)

	// Update
	err = m.Update(4, 100)
	assert.NoError(t, err)

	// Lookup
	value, err = m.LookupInt(4)
	assert.NoError(t, err)
	assert.Equal(t, 100, value)

	// Delete
	err = m.Delete(4)
	assert.NoError(t, err)

	// For BPF arrays - all items are present anytime
	// if item wasn't "inserted" before - expect default value - zero
	value, err = m.LookupInt(4)
	assert.NoError(t, err)
	assert.Equal(t, 0, value)
}

func TestMockMapHash(t *testing.T) {
	// Destroy / Create
	m := MockMaps["map_hash"].(*MockMap)
	err := m.Destroy()
	require.NoError(t, err)
	err = m.Create()
	require.NoError(t, err)

	// Delete non existing item - prohibited
	err = m.Delete(11)
	assert.Error(t, err)

	// Update non existing item is the same - error
	err = m.Update(11, 100)
	assert.Error(t, err)

	err = m.Insert(11, 100)
	assert.NoError(t, err)

	// Lookup / update / lookup (on existing item)
	value, err := m.LookupInt(11)
	assert.NoError(t, err)
	assert.Equal(t, 100, value)

	err = m.Update(11, 200)
	assert.NoError(t, err)

	value, err = m.LookupInt(11)
	assert.NoError(t, err)
	assert.Equal(t, 200, value)

	//upsert non existing item
	err = m.Upsert(12, 101)
	assert.NoError(t, err)

	value, err = m.LookupInt(12)
	assert.NoError(t, err)
	assert.Equal(t, 101, value)

	//upsert existing item
	err = m.Upsert(12, 102)
	assert.NoError(t, err)

	value, err = m.LookupInt(12)
	assert.NoError(t, err)
	assert.Equal(t, 102, value)

	// Delete
	err = m.Delete(11)
	assert.NoError(t, err)

	// Delete (now non existing item)
	err = m.Delete(11)
	assert.Error(t, err)
}

func TestArrayOfMaps(t *testing.T) {
	// Inner map
	template := MockMap{
		Type:       goebpf.MapTypeArray,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 10,
	}

	// Create special map which contains other maps as value
	outer := &MockMap{
		Type:       goebpf.MapTypeArrayOfMaps,
		MaxEntries: 10,
	}
	err := outer.Create()
	assert.NoError(t, err)

	// Create new map based on template / add one value
	inner := template.CloneTemplate()
	err = inner.Create()
	assert.NoError(t, err)
	// Put it into outer map (map of maps)
	err = outer.Update(0, inner.GetFd())
	assert.NoError(t, err)

	// Ensure that outer map contains proper fd
	fd, err := outer.LookupInt(0)
	assert.NoError(t, err)
	assert.Equal(t, inner.GetFd(), fd)
}

func TestGetNextKeyString(t *testing.T) {
	// Create map
	m := MockMap{
		Type:       goebpf.MapTypeHash,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 10,
	}
	err := m.Create()
	assert.NoError(t, err)

	mapData := map[string]string{
		"key1": "val1",
		"key2": "val2",
		"key3": "val3",
	}

	result := map[string]string{}

	// Insert items into hash map
	for key, value := range mapData {
		err = m.Insert(key, value)
		assert.NoError(t, err)
	}
	var currentKey string
	for {
		nextKey, err := m.GetNextKeyString(currentKey)
		if err != nil {
			break
		}
		val, err := m.LookupString(nextKey)
		assert.NoError(t, err)
		assert.Equal(t, mapData[nextKey], string(val))
		result[nextKey] = val
		currentKey = nextKey
	}
	assert.Equal(t, mapData, result)
}

func TestGetNextKeyInt(t *testing.T) {
	// Create map
	m := MockMap{
		Type:       goebpf.MapTypeHash,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 10,
	}
	err := m.Create()
	assert.NoError(t, err)

	mapData := map[int]int{
		1234: 4321,
		5678: 8765,
		9012: 2109,
	}

	result := map[int]int{}

	// Insert items into hash map
	for key, value := range mapData {
		err = m.Insert(key, value)
		assert.NoError(t, err)
	}
	var currentKey int
	for {
		nextKey, err := m.GetNextKeyInt(currentKey)
		if err != nil {
			break
		}
		val, err := m.LookupInt(nextKey)
		assert.NoError(t, err)
		assert.Equal(t, mapData[nextKey], int(val))
		result[nextKey] = val
		currentKey = nextKey
	}
	assert.Equal(t, mapData, result)
}
