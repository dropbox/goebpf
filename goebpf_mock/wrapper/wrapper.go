// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

// Package wrapper is wrapper for "cross compiled" XDP in order to call it right from GO
// P.S. this should be as part of *_test.go files, however, GO does not support
// using import "C" from tests... :-(
package wrapper

/*
#include "../../bpf_helpers.h"

// Since eBPF mock package is optional and have definition of "__maps_head" symbol
// it may cause link error, so defining weak symbol here as well
struct __create_map_def maps_head;
__attribute__((weak)) struct __maps_head_def *__maps_head = (struct __maps_head_def*) &maps_head;

BPF_MAP_DEF(map_hash) = {
    .map_type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u64),
    .value_size = sizeof(__u32),
    .max_entries = 50,
};
BPF_MAP_ADD(map_hash);

BPF_MAP_DEF(map_array) = {
    .map_type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 10,
};
BPF_MAP_ADD(map_array);
*/
import "C"

// Dummy is simply nothing - just to force golang to include empty package
const Dummy = 0
