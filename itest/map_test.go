// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

package itest

import (
	"encoding/binary"
	"os"
	"testing"

	"github.com/dropbox/goebpf"
	"github.com/stretchr/testify/suite"
)

type mapTestSuite struct {
	suite.Suite
}

// CRUD for BPF hash maps
func (ts *mapTestSuite) TestMapHash() {
	// Create map
	m := &goebpf.EbpfMap{
		Type:       goebpf.MapTypeHash,
		KeySize:    8,
		ValueSize:  8,
		MaxEntries: 10,
	}
	err := m.Create()
	ts.NoError(err)

	// Insert few items into hash map
	err = m.Insert("str1", "value1")
	ts.NoError(err)
	err = m.Insert("str123", "value2")
	ts.NoError(err)
	err = m.Insert("empty", "")
	ts.NoError(err)

	//use upsert to insert
	err = m.Upsert("upsert1", "upvalue1")
	ts.NoError(err)
	err = m.Upsert("upsert2", "upvalue2")
	ts.NoError(err)

	// Lookup(generic) previously inserted item
	bval, err := m.Lookup("str123")
	ts.NoError(err)
	ts.Equal([]byte("value2\x00\x00"), bval)

	// Lookup(string)
	sval, err := m.LookupString("str1")
	ts.NoError(err)
	ts.Equal("value1", sval)

	sval, err = m.LookupString("empty")
	ts.NoError(err)
	ts.Equal("", sval)

	// Lookup upserted items(string)
	sval, err = m.LookupString("upsert1")
	ts.NoError(err)
	ts.Equal("upvalue1", sval)

	sval, err = m.LookupString("upsert2")
	ts.NoError(err)
	ts.Equal("upvalue2", sval)

	// Update item
	err = m.Update("str123", "newval")
	ts.NoError(err)
	// Lookup again - to verify that value got updated
	sval, err = m.LookupString("str123")
	ts.NoError(err)
	ts.Equal("newval", sval)

	// update item using upsert
	err = m.Upsert("upsert1", "newupval")
	ts.NoError(err)
	// Lookup again - to verify that value got updated
	sval, err = m.LookupString("upsert1")
	ts.NoError(err)
	ts.Equal("newupval", sval)

	// Delete item
	err = m.Delete("str1")
	ts.NoError(err)
	// Lookup again - to be sure that element has been deleted
	_, err = m.Lookup("str1")
	ts.Error(err)

	// Negative tests
	// Insert already existing item
	err = m.Insert("str123", "value2")
	ts.Error(err)
	// Update non-existing item
	err = m.Update("dummy", "1")
	ts.Error(err)
}

func (ts *mapTestSuite) TestMapArrayInt16() {
	// Create map
	m := &goebpf.EbpfMap{
		Type:       goebpf.MapTypeArray,
		ValueSize:  2, // uint16
		MaxEntries: 5,
	}
	err := m.Create()
	ts.NoError(err)

	// Array type doesn't support add/delete items, so
	// update all items (by default all items are initialized to zero)
	for i := 0; i < m.MaxEntries; i++ {
		err := m.Update(i, i+1)
		ts.NoError(err)
	}

	// Lookup all items - ensure that it works great :)
	for i := 0; i < m.MaxEntries; i++ {
		res, err := m.LookupInt(i)
		ts.NoError(err)
		ts.Equal(i+1, res)
	}

	// Some corner values
	runs := []int{
		0,
		0xff,
		256,
		4095,
		0xfff,
		0xffff,
	}
	for _, r := range runs {
		err := m.Update(0, r)
		ts.NoError(err)
		val, err := m.LookupInt(0)
		ts.NoError(err)
		ts.Equal(r, val)
	}

	// Negative: int too large
	err = m.Update(0, 0xfffff)
	ts.Error(err)

	// Non existing item
	_, err = m.LookupInt(100)
	ts.Error(err)
}

func (ts *mapTestSuite) TestMapArrayInt() {
	m := &goebpf.EbpfMap{
		Type:       goebpf.MapTypeArray,
		ValueSize:  8,
		MaxEntries: 5,
	}
	err := m.Create()
	ts.NoError(err)

	// Test some int values
	runs := []int{
		0,
		-1,
		-10000000000,
		0x7fffffffffffffff,
		0xff,
		256,
		4095,
		0xfff,
		0xffff,
	}
	for _, r := range runs {
		err := m.Update(0, r)
		ts.NoError(err)
		val, err := m.LookupInt(0)
		ts.NoError(err)
		ts.Equal(r, val)
	}
}

// Array type doesn't support add/delete items, only update
func (ts *mapTestSuite) TestMapArrayUInt64() {
	m := &goebpf.EbpfMap{
		Type:       goebpf.MapTypeArray,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 5,
	}
	err := m.Create()
	ts.NoError(err)

	// Update all items (By default all items are initialized to zero)
	start := uint64(1 << 61) // 0xFFFFFFFFFFFFFFF8 (3 bits remaining)
	for i := 0; i < m.MaxEntries; i++ {
		err := m.Update(i, start+uint64(i))
		ts.NoError(err)
	}

	// Lookup all items - ensure that it works great :)
	for i := 0; i < m.MaxEntries; i++ {
		res, err := m.LookupUint64(i)
		ts.NoError(err)
		ts.Equal(start+uint64(i), res)
	}
}

// Long Prefix Match Trie test
func (ts *mapTestSuite) TestMapLPMTrieIPv4() {
	// Create map
	m := &goebpf.EbpfMap{
		Type:       goebpf.MapTypeLPMTrie,
		KeySize:    8, // prefix size + ipv4
		ValueSize:  8,
		MaxEntries: 10,
	}
	err := m.Create()
	ts.NoError(err)

	// Insert few subnets
	err = m.Insert(goebpf.CreateLPMtrieKey("192.168.0.0/16"), "value16")
	ts.NoError(err)
	err = m.Insert(goebpf.CreateLPMtrieKey("192.168.0.0/24"), "value24")
	ts.NoError(err)

	// Perform lookup (it is usually done from XDP program - here is only for integration tests)
	val1, err := m.LookupString(goebpf.CreateLPMtrieKey("192.168.0.10"))
	ts.NoError(err)
	ts.Equal("value24", val1)

	// Negative lookup: IP doesn't belong to any range
	_, err = m.LookupString(goebpf.CreateLPMtrieKey("10.10.10.10"))
	ts.Error(err)

	// "Default route" :)
	err = m.Insert(goebpf.CreateLPMtrieKey("0.0.0.0/0"), "value0")
	ts.NoError(err)

	// Lookup any IP
	val2, err := m.LookupString(goebpf.CreateLPMtrieKey("222.222.222.222"))
	ts.NoError(err)
	ts.Equal("value0", val2)
}

func (ts *mapTestSuite) TestMapLPMTrieIPv6() {
	// Create map
	m := &goebpf.EbpfMap{
		Type:       goebpf.MapTypeLPMTrie,
		KeySize:    20, // prefix len + ipv6
		ValueSize:  8,
		MaxEntries: 10,
	}
	err := m.Create()
	ts.NoError(err)

	// Insert few subnets
	err = m.Insert(goebpf.CreateLPMtrieKey("fafa::fbf8/120"), "value120")
	ts.NoError(err)
	err = m.Insert(goebpf.CreateLPMtrieKey("fafa::fbf8/125"), "val125")
	ts.NoError(err)

	// Perform lookup (it is usually done from XDP program - here is only for integration tests)
	val1, err := m.LookupString(goebpf.CreateLPMtrieKey("fafa::fbfa"))
	ts.NoError(err)
	ts.Equal("val125", val1)

	// Negative lookup: IP doesn't belong to any range
	_, err = m.LookupString(goebpf.CreateLPMtrieKey("1afa::fbfa"))
	ts.Error(err)

	// "Default route" :)
	err = m.Insert(goebpf.CreateLPMtrieKey("::/0"), "value0")
	ts.NoError(err)

	// Lookup any IP
	val2, err := m.LookupString(goebpf.CreateLPMtrieKey("1111::1111"))
	ts.NoError(err)
	ts.Equal("value0", val2)
}

func (ts *mapTestSuite) TestArrayOfMaps() {
	// Inner map template
	templ := goebpf.EbpfMap{
		Type:       goebpf.MapTypeArray,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 10,
	}
	m := templ
	err := m.Create()
	ts.NoError(err)

	// Create special map which contains other maps as value
	mm := &goebpf.EbpfMap{
		Type:       goebpf.MapTypeArrayOfMaps,
		MaxEntries: 10,
		InnerMapFd: m.GetFd(),
	}
	err = mm.Create()
	ts.NoError(err)

	// Create few inner maps - and insert them into array of maps (m)
	for i := 0; i < 5; i++ {
		m1 := templ
		err = m1.Create()
		ts.NoError(err)
		// Insert it into outer map (main map)
		err = mm.Update(i, m1.GetFd())
		ts.NoError(err)
	}
}

func (ts *mapTestSuite) TestHashOfMaps() {
	// Inner map template
	templ := &goebpf.EbpfMap{
		Type:       goebpf.MapTypeArray,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 10,
	}
	m := templ
	err := m.Create()
	ts.NoError(err)

	// Create special map which contains other maps as value
	mm := &goebpf.EbpfMap{
		Type:       goebpf.MapTypeHashOfMaps,
		KeySize:    4,
		MaxEntries: 10,
		InnerMapFd: m.GetFd(),
	}
	err = mm.Create()
	ts.NoError(err)

	// Create few inner maps - and insert them into hash of maps (m)
	for i := 0; i < 5; i++ {
		m1 := templ
		err = m.Create()
		ts.NoError(err)
		// Insert it into outer hash map (main map)
		err = mm.Insert(i, m1.GetFd())
		ts.NoError(err)
	}
}

// Array of bpf programs.
// Since we don't have BPF programs loaded - we'll simply try to create this map.
// Additional tests are in xdp_test.go
func (ts *mapTestSuite) TestMapProgArray() {
	// Create map
	m := &goebpf.EbpfMap{
		Type:       goebpf.MapTypeProgArray,
		MaxEntries: 5,
	}
	err := m.Create()
	ts.NoError(err)
}

// Persistent map test
func (ts *mapTestSuite) TestMapPersistent() {
	// Create system wide map (i.e. regular create with object pinning to given path)
	cnt := 5
	path := bpfPath + "/test"
	m1 := &goebpf.EbpfMap{
		Type:           goebpf.MapTypeArray,
		ValueSize:      4,
		MaxEntries:     cnt,
		PersistentPath: path,
	}
	err := m1.Create()
	ts.NoError(err)

	// Ensure that special file in BPF fs present
	ts.FileExists(path)

	// Fill map with some values
	for i := 0; i < cnt; i++ {
		m1.Update(i, i)
	}

	// Since last map is declared as system wide and present at given location
	// it is possible to "create" one more the same map points to the same location.
	// Map.Create() will not create new map, it will call bpf_obj_get() instead.
	m2 := m1.CloneTemplate()
	m2.Create()

	// Lookup items (they've been inserted before in m1)
	for i := 0; i < cnt; i++ {
		res, err := m2.LookupInt(i)
		ts.NoError(err)
		ts.Equal(i, res)
	}

	// Unlink file
	err = os.Remove(path)
	ts.NoError(err)

	// Close all maps
	err = m1.Close()
	ts.NoError(err)

	err = m2.Close()
	ts.NoError(err)
}

// Double close negative test
func (ts *mapTestSuite) TestMapDoubleClose() {
	m := &goebpf.EbpfMap{
		Type:       goebpf.MapTypeArray,
		ValueSize:  4,
		MaxEntries: 4,
	}
	// Try to close non-created map
	err := m.Close()
	ts.Error(err)

	err = m.Create()
	ts.NoError(err)

	// Finally close it twice
	err = m.Close()
	ts.NoError(err)
	err = m.Close()
	ts.Error(err)
}

func (ts *mapTestSuite) TestMapFromExistingByFd() {
	// Create map which will be used to create new from
	m1 := &goebpf.EbpfMap{
		Name:       "test",
		Type:       goebpf.MapTypeArray,
		ValueSize:  4,
		MaxEntries: 4,
	}
	err := m1.Create()
	ts.NoError(err)

	// Create map structure from already existing map in kernel
	// by its FD (not ID! since this is the same process)
	m2, err := goebpf.NewMapFromExistingMapByFd(m1.GetFd())
	ts.NoError(err)
	ts.Equal(m1.GetFd(), m2.GetFd())

	// Create() should not re-create map, just re-use existing fd
	m2.Create()
	ts.Equal(m1, m2)
}

func (ts *mapTestSuite) TestGetNextKeyString() {
	// Create map
	m := &goebpf.EbpfMap{
		Type:       goebpf.MapTypeHash,
		KeySize:    8,
		ValueSize:  8,
		MaxEntries: 10,
	}
	err := m.Create()
	ts.NoError(err)

	mapData := map[string]string{
		"key1": "val1",
		"key2": "val2",
		"key3": "val3",
	}

	result := map[string]string{}

	// Insert items into hash map
	for key, value := range mapData {
		err = m.Insert(key, value)
		ts.NoError(err)
	}
	var currentKey string
	for {
		nextKey, err := m.GetNextKeyString(currentKey)
		if err != nil {
			break
		}
		val, err := m.LookupString(nextKey)
		ts.NoError(err)
		ts.Equal(mapData[nextKey], string(val))
		result[nextKey] = val
		currentKey = nextKey
	}
	ts.Equal(mapData, result)
}

func (ts *mapTestSuite) TestGetNextKeyInt() {
	// Create map
	m := &goebpf.EbpfMap{
		Type:       goebpf.MapTypeHash,
		KeySize:    8,
		ValueSize:  8,
		MaxEntries: 10,
	}
	err := m.Create()
	ts.NoError(err)

	mapData := map[int]int{
		1234: 4321,
		5678: 8765,
		9012: 2109,
	}

	result := map[int]int{}

	// Insert items into hash map
	for key, value := range mapData {
		err = m.Insert(key, value)
		ts.NoError(err)
	}
	var currentKey int
	for {
		nextKey, err := m.GetNextKeyInt(currentKey)
		if err != nil {
			break
		}
		val, err := m.LookupInt(nextKey)
		ts.NoError(err)
		ts.Equal(mapData[nextKey], int(val))
		result[nextKey] = val
		currentKey = nextKey
	}
	ts.Equal(mapData, result)
}

func (ts *mapTestSuite) TestMapFromExistingByPath() {
	path := bpfPath + "/test"

	// Make sure we're not loading an old map
	os.Remove(path)
	ts.NoFileExists(path)

	// Create map which will be used to create new from
	m1 := &goebpf.EbpfMap{
		Name:           "test",
		Type:           goebpf.MapTypeArray,
		ValueSize:      4,
		MaxEntries:     4,
		PersistentPath: path,
	}
	err := m1.Create()
	ts.NoError(err)

	// Create map structure from already existing map in kernel by its path
	m2, err := goebpf.NewMapFromExistingMapByPath(m1.PersistentPath)
	ts.NoError(err)

	// Insert to the original map object
	err = m1.Update(2, 1337)
	ts.NoError(err)

	// Lookup from the newly opened map object
	res, err := m2.LookupInt(2)
	ts.NoError(err)
	ts.Equal(1337, res)

	// The map should be the same except for the fd
	ts.Equal(m1.Name, m2.Name)
	ts.Equal(m1.Type, m2.Type)
	ts.Equal(m1.ValueSize, m2.ValueSize)
	ts.Equal(m1.MaxEntries, m2.MaxEntries)
	ts.Equal(m1.MaxEntries, m2.MaxEntries)
	ts.Equal(m1.PersistentPath, m2.PersistentPath)

	os.Remove(path)
}

func (ts *mapTestSuite) TestMapPerCpuValues() {
	// Create a map with percpu values
	m := &goebpf.EbpfMap{
		Name:       "test",
		Type:       goebpf.MapTypePerCPUHash,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 16,
	}
	err := m.Create()
	ts.NoError(err)

	// Prepare values for insert
	numCpus, err := goebpf.GetNumOfPossibleCpus()
	ts.NoError(err)

	// The values need to be padded to 8 bytes
	val := make([]byte, 8*numCpus)
	for i := 0; i < numCpus; i++ {
		binary.LittleEndian.PutUint32(val[i*8:i*8+4], uint32(i))
	}

	// Insert the values
	err = m.Insert("str1", val)
	ts.NoError(err)

	// Lookup the inserted values
	bval, err := m.Lookup("str1")
	ts.NoError(err)
	for i := 0; i < numCpus; i++ {
		v := binary.LittleEndian.Uint32(bval[i*8 : i*8+4])
		ts.EqualValues(i, v)
	}
}

// Run suite
func TestMapSuite(t *testing.T) {
	suite.Run(t, new(mapTestSuite))
}
