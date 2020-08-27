// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

package goebpf_mock

// eBPF maps golang mock implementation for testing purposes.
// The idea behind is make any BPF program unit-testable right from GO

/*
#include <stdint.h>
#include <sys/queue.h>
#include <stdlib.h>

#include "../bpf_helpers.h"

#define MAX_KEY_SIZE	32

struct bpf_map_item {
	SLIST_ENTRY(bpf_map_item) next;
	uint8_t key[MAX_KEY_SIZE];	// key is fixed size
	uint8_t value[];			// value is flexible size
};
SLIST_HEAD(bpf_map_data_head, bpf_map_item);

// Define previously declared list head
struct __create_map_def maps_head;
struct __maps_head_def *__maps_head = (struct __maps_head_def*) &maps_head;

static int is_map_type_array(struct bpf_map_def *def)
{
	switch (def->map_type) {
		case BPF_MAP_TYPE_ARRAY:
		case BPF_MAP_TYPE_PROG_ARRAY:
		case BPF_MAP_TYPE_PERF_EVENT_ARRAY:
		case BPF_MAP_TYPE_PERCPU_ARRAY:
		case BPF_MAP_TYPE_CGROUP_ARRAY:
		case BPF_MAP_TYPE_ARRAY_OF_MAPS:
			return 1;
		default:
			return 0;
	}
}

static struct __create_map_def *bpf_map_find(const void *map)
{
	struct __create_map_def *item = NULL;

	// Search for map
	SLIST_FOREACH(item, __maps_head, next) {
		if (item->map_def == map) {
			break;
		}
	}

	// item will be null if loop ended without condition matched
	return item;
}

static struct bpf_map_item *bpf_add_map_item(struct __create_map_def *map, const void *key)
{
	// Allocate memory for new element: value_size + metadata
	struct bpf_map_item *item;
	size_t item_size = sizeof(*item) + map->map_def->value_size;
	item = malloc(item_size);
	if (!item) {
		// Out of memory
		return NULL;
	}

	// Initialize item to zeros
	memset(item, 0, item_size);
	// Copy key
	memcpy(item->key, key, map->map_def->key_size);

	// Insert it
	SLIST_INSERT_HEAD((struct bpf_map_data_head*)&map->map_data, item, next);

	return item;
}

void bpf_remove_map_item(struct __create_map_def *map, struct bpf_map_item *item)
{
	SLIST_REMOVE((struct bpf_map_data_head*) &map->map_data, item, bpf_map_item, next);
	free(item);
}

static void *bpf_find_item_by_key(struct __create_map_def *map, const void *key)
{
	// Simple linear search: iterate by all items and compare key, O(n)
	struct bpf_map_item *item = NULL;
	SLIST_FOREACH(item, (struct bpf_map_data_head*)&map->map_data, next) {
		if (memcmp(key, item->key, map->map_def->key_size) == 0) {
			// Key match, found!
			break;
		}
	}
	return item;
}

static void *bpf_find_next_item_by_key(struct __create_map_def *map, const void *key)
{
	struct bpf_map_data_head *head = (struct bpf_map_data_head*) &map->map_data;
	struct bpf_map_item *item = NULL;
	SLIST_FOREACH(item, head, next) {
		if (memcmp(key, item->key, map->map_def->key_size) == 0) {
			struct bpf_map_item *nextitem = SLIST_NEXT(item, next);
			// if next key points to the head (first item), return NULL
			if ((void *)nextitem == (void*)item) {
				return NULL;
			}
			return nextitem;
		}
	}
	// if no match, return first item
	return SLIST_FIRST(head);
}

static void* bpf_map_create(__u32 map_type, __u32 key_size, __u32 value_size, __u32 max_entries)
{
	// Allocate structure to store information about new map (usually done by BPF_MAP_ADD() macro)
	struct __create_map_def *new_map = malloc(sizeof(struct __create_map_def));
	if (!new_map) {
		// out of memory?
		return NULL;
	}
	// Allocate map definition (usually it is statically defined by BPF_MAP_DEF() macro)
	struct bpf_map_def *new_map_def = malloc(sizeof(struct bpf_map_def));
	if (!new_map_def) {
		// out of memory?
		free(new_map);
		return NULL;
	}

	// Initialize new map with zeros
	memset(new_map, 0, sizeof(struct __create_map_def));
	memset(new_map_def, 0, sizeof(struct bpf_map_def));

	// Save map parameters
	new_map->map_def = new_map_def;
	new_map_def->map_type = map_type;
	new_map_def->key_size = key_size;
	new_map_def->value_size = value_size;
	new_map_def->max_entries = max_entries;

	// Insert new item into maps list
	SLIST_INSERT_HEAD(__maps_head, new_map, next);

	return new_map_def;
}

static int bpf_map_destroy(const void *fd)
{
	struct __create_map_def *map = bpf_map_find(fd);

	// If map not found
	if (!map) {
		return -1;
	}

	// Delete all items
	struct bpf_map_data_head *head = (struct bpf_map_data_head*) &map->map_data;
	while (!SLIST_EMPTY(head)) {
		struct bpf_map_item *item = SLIST_FIRST(head);
		bpf_remove_map_item(map, item);
	}

	// Intentionally do not free map definition since it may
	// still in use from XDP program side
	// It may cause memory leak for dynamically created maps.
	// Since mock maps must be used only for testing purposes
	// it seems to be good trade off between complexity and simplicity.

	return 0;
}

void *bpf_map_lookup_elem(const void *fd, const void *key)
{
	struct __create_map_def *map = bpf_map_find(fd);

	// If map not found
	if (!map) {
		return NULL;
	}

	// Lookup item in map
	struct bpf_map_item *item = bpf_find_item_by_key(map, key);

	// Array based map types requires special handling:
	// They are always fixed size therefore all items must be present
	// all times.
	if (!item && is_map_type_array(map->map_def)) {
		item = bpf_add_map_item(map, key);
	}

	if (!item) {
		return NULL;
	}

	// Special handling for array/map of maps:
	// Original BPF implementation has special handling of these types
	// and returns pure fd for map instead of pointer, so, following it...
	switch (map->map_def->map_type) {
	case BPF_MAP_TYPE_ARRAY_OF_MAPS:
	case BPF_MAP_TYPE_HASH_OF_MAPS:
		return (void*)*((size_t*)item->value);
	default:
		return item->value;
	}
}

int bpf_map_update_elem(const void *fd, const void *key, const void *value, __u64 flags)
{
	struct __create_map_def *map = bpf_map_find(fd);

	// If map not found
	if (!map) {
		return -1;
	}

	// Add item if not exists yet
	struct bpf_map_item *item = bpf_find_item_by_key(map, key);
	if (!item) {
		item = bpf_add_map_item(map, key);
	}

	if (!item) {
		return -1;
	}

	// Update item's value
	memcpy(item->value, value, map->map_def->value_size);

	return 0;
}

int bpf_map_get_next_key(const void *fd, void *key, void *next_key)
{
	struct __create_map_def *map = bpf_map_find(fd);

	// If map not found
	if (!map) {
		return -1;
	}

	// get next key following provided key
	struct bpf_map_item *item = bpf_find_next_item_by_key(map, key);

	if (!item) {
		return -1;
	}

	memcpy(next_key, item->key, map->map_def->key_size);

	return 0;
}

int bpf_map_delete_elem(const void *fd, const void *key)
{
	struct __create_map_def *map = bpf_map_find(fd);

	// If map not found
	if (!map) {
		return -1;
	}

	struct bpf_map_item *item = bpf_find_item_by_key(map, key);
	if (item) {
		bpf_remove_map_item(map, item);
		return 0;
	}

	// Special case for array based maps: should never return error
	// if item not present (array is interpreted as fixed size container)
	return is_map_type_array(map->map_def) ? 0 : -1;
}

// Helpers for GO side //

// BPF element lookup - implementation for GO
int bpf_map_lookup_elem_golang(const void *fd, const void *key, void *buf)
{
	struct __create_map_def *map = bpf_map_find(fd);

	// If map not found
	if (!map) {
		return -1;
	}

	// Lookup item in map
	struct bpf_map_item *item = bpf_find_item_by_key(map, key);

	// Array based map types requires special handling:
	// arrays are always fixed size therefore all items must be present
	// all times.
	if (!item && is_map_type_array(map->map_def)) {
		item = bpf_add_map_item(map, key);
	}

	if (!item) {
		return -1;
	}

	memcpy(buf, item->value, map->map_def->value_size);

	return 0;
}

// Returns map fd / fixes key / value sizes since they may be
// omitted in definition.
static void* fix_def_and_get_map_fd(struct __create_map_def* item)
{
	// Fix default values for key/value size
	struct bpf_map_def *def = item->map_def;

	if (def->key_size == 0) {
		def->key_size = 4;
	}
	if (def->value_size == 0) {
		def->value_size = 8;
	}

	return item->map_def;
}

// Returns head of single linked list defined by BPF_MAP_ADD() macro
static struct __create_map_def* bpf_map_get_head()
{
	return __maps_head->slh_first;
}

// Returns next element from slist
static struct __create_map_def* bpf_map_get_next(struct __create_map_def* curr)
{
	return SLIST_NEXT(curr, next);
}

*/
import "C"

import (
	"errors"
	"unsafe"

	"github.com/dropbox/goebpf"
)

// MockMap defines eBPF mockmap and implements Map interface
type MockMap struct {
	fd         unsafe.Pointer
	Name       string
	Type       goebpf.MapType
	KeySize    int
	ValueSize  int
	MaxEntries int
}

// MockMaps is list of cross compiled/linked eBPF maps into GO executable
// This map will contain all eBPF maps defined in eBPF program
var MockMaps map[string]goebpf.Map

func init() {
	// Initialize mock map definitions from statically linked cross compiled BPF program
	MockMaps = make(map[string]goebpf.Map)
	// Iterate over all maps defined in BPF program
	for res := C.bpf_map_get_head(); res != nil; res = C.bpf_map_get_next(res) {
		name := C.GoString(res.name)
		// Since map definition can be linked multiple times, skip duplicates
		if _, ok := MockMaps[name]; ok {
			continue
		}
		m := &MockMap{
			fd:         C.fix_def_and_get_map_fd(res),
			Name:       C.GoString(res.name),
			Type:       goebpf.MapType(res.map_def.map_type),
			KeySize:    int(res.map_def.key_size),
			ValueSize:  int(res.map_def.value_size),
			MaxEntries: int(res.map_def.max_entries),
		}

		m.Create()
		MockMaps[m.Name] = m
	}
}

// Create creates MockMap
func (m *MockMap) Create() error {
	if m.KeySize == 0 {
		m.KeySize = 4
	}
	if m.ValueSize == 0 {
		m.ValueSize = 8
	}
	if m.fd == nil {
		m.fd = C.bpf_map_create(
			C.__u32(m.Type),
			C.__u32(m.KeySize),
			C.__u32(m.ValueSize),
			C.__u32(m.MaxEntries),
		)
		if m.fd == nil {
			return errors.New("bpf_map_create() failed")
		}
	}

	return nil
}

// Close does nothing - just to implement Map interface
func (m *MockMap) Close() error {
	m.fd = nil

	return nil
}

// CloneTemplate creates clone of current map
func (m *MockMap) CloneTemplate() goebpf.Map {
	res := *m
	res.fd = nil

	return &res
}

// Destroy destroys mock map
func (m *MockMap) Destroy() error {
	res := C.bpf_map_destroy(m.fd)

	if res != 0 {
		return errors.New("mock map destroy failed")
	}

	return nil
}

// Lookup is generic implementation for all other Lookups (string, int, etc)
func (m *MockMap) Lookup(ikey interface{}) ([]byte, error) {
	// Convert key into bytes
	key, err := goebpf.KeyValueToBytes(ikey, m.KeySize)
	if err != nil {
		return nil, err
	}

	// Buffer where C part will copy value into
	var val = make([]byte, m.ValueSize)
	res := C.bpf_map_lookup_elem_golang(m.fd,
		unsafe.Pointer(&key[0]),
		unsafe.Pointer(&val[0]),
	)

	if res != 0 {
		return nil, errors.New("bpf_map_lookup_elem_golang() failed (not found?)")
	}

	return val, nil
}

// LookupString perform lookup and returns GO string from NULL terminated C string
func (m *MockMap) LookupString(ikey interface{}) (string, error) {
	val, err := m.Lookup(ikey)
	if err != nil {
		return "", err
	}

	return goebpf.NullTerminatedStringToString(val), nil
}

// LookupInt perform lookup and returns int
func (m *MockMap) LookupInt(ikey interface{}) (int, error) {
	val, err := m.LookupUint64(ikey)

	return int(val), err
}

// LookupUint64 perform lookup and returns uint64
func (m *MockMap) LookupUint64(ikey interface{}) (uint64, error) {
	if m.ValueSize > 8 {
		return 0, errors.New("Value is too large to fit int")
	}
	val, err := m.Lookup(ikey)
	if err != nil {
		return 0, err
	}

	return goebpf.ParseFlexibleIntegerLittleEndian(val), nil
}

// Insert insert new element into mock map.
// Valid only for non array maps.
func (m *MockMap) Insert(ikey interface{}, ivalue interface{}) error {
	// Convert key/value into bytes
	key, err := goebpf.KeyValueToBytes(ikey, m.KeySize)
	if err != nil {
		return err
	}

	val, err := goebpf.KeyValueToBytes(ivalue, m.ValueSize)
	if err != nil {
		return err
	}

	res := C.bpf_map_update_elem(
		unsafe.Pointer(uintptr(m.fd)),
		unsafe.Pointer(&key[0]),
		unsafe.Pointer(&val[0]),
		0,
	)

	if res != 0 {
		return errors.New("bpf_map_update_elem() failed")
	}

	return nil
}

// Update updates existing element in mock map
func (m *MockMap) Update(ikey interface{}, ivalue interface{}) error {
	// Hash based maps require item to be exists before update
	if m.Type == goebpf.MapTypeHash {
		_, err := m.Lookup(ikey)
		if err != nil {
			return err
		}
	}

	return m.Insert(ikey, ivalue)
}

// Upsert updates existing element in mock map, or inserts one if it did not exist yet
func (m *MockMap) Upsert(ikey interface{}, ivalue interface{}) error {
	return m.Insert(ikey, ivalue)
}

// Delete deletes element from mock map
// Valid only for non array map types
func (m *MockMap) Delete(ikey interface{}) error {
	// Convert key into bytes
	key, err := goebpf.KeyValueToBytes(ikey, m.KeySize)
	if err != nil {
		return err
	}

	res := C.bpf_map_delete_elem(
		unsafe.Pointer(uintptr(m.fd)),
		unsafe.Pointer(&key[0]),
	)

	if res != 0 {
		return errors.New("bpf_map_delete_elem() failed")
	}

	return nil
}

// GetNextKey gets the next key of the provided key
func (m *MockMap) GetNextKey(ikey interface{}) ([]byte, error) {
	// Convert key into bytes
	key, err := goebpf.KeyValueToBytes(ikey, m.KeySize)
	if err != nil {
		return nil, err
	}
	var nextKey = make([]byte, m.KeySize)
	res := C.bpf_map_get_next_key(m.fd,
		unsafe.Pointer(&key[0]),
		unsafe.Pointer(&nextKey[0]),
	)

	if res != 0 {
		return nil, errors.New("bpf_map_get_next_key() failed (last key?)")
	}

	return nextKey, nil
}

func (m *MockMap) GetNextKeyString(ikey interface{}) (string, error) {
	nextKey, err := m.GetNextKey(ikey)
	if err != nil {
		return "", err
	}
	return goebpf.NullTerminatedStringToString(nextKey), nil
}

func (m *MockMap) GetNextKeyInt(ikey interface{}) (int, error) {
	nextKey, err := m.GetNextKeyUint64(ikey)
	return int(nextKey), err
}

func (m *MockMap) GetNextKeyUint64(ikey interface{}) (uint64, error) {
	if m.KeySize > 8 {
		return 0, errors.New("Value is too large to fit int")
	}
	nextKey, err := m.GetNextKey(ikey)
	if err != nil {
		return 0, err
	}
	return goebpf.ParseFlexibleIntegerLittleEndian(nextKey), nil
}

// GetFd returns mock file descriptor of map
func (m *MockMap) GetFd() int {
	return int(uintptr(m.fd))
}

// GetName returns mock map name
func (m *MockMap) GetName() string {
	return m.Name
}

// GetType returns mock map type
func (m *MockMap) GetType() goebpf.MapType {
	return m.Type
}

// CleanupAllMockMaps re-creates all mock maps
// Useful for unittests
func CleanupAllMockMaps() {
	for _, m := range MockMaps {
		mm := m.(*MockMap)
		mm.Destroy()
		mm.Create()
	}
}
