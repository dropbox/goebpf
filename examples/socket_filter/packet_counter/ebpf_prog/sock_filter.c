// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

// Very simple SocketFilter program to count packets.

#include "bpf_helpers.h"

// eBPF map to packet counter
BPF_MAP_DEF(counter) = {
    .map_type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 1,
};
BPF_MAP_ADD(counter);


// Socket Filter program //
SEC("socket_filter")
int packet_counter(struct __sk_buff *skb) {
  // Simply increase counter
  __u32 idx = 0;
  __u64 *value = bpf_map_lookup_elem(&counter, &idx);
  if (value) {
      *value += 1;
  }

  return SOCKET_FILTER_ALLOW;
}

char _license[] SEC("license") = "GPLv2";
