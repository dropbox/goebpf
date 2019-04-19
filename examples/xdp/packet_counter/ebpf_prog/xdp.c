// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

// Very simple XDP program for eBPF library integration tests

#include "bpf_helpers.h"

// Ethernet header
struct ethhdr {
  __u8 h_dest[6];
  __u8 h_source[6];
  __u16 h_proto;
} __attribute__((packed));

// IPv4 header
struct iphdr {
  __u8 ihl : 4;
  __u8 version : 4;
  __u8 tos;
  __u16 tot_len;
  __u16 id;
  __u16 frag_off;
  __u8 ttl;
  __u8 protocol;
  __u16 check;
  __u32 saddr;
  __u32 daddr;
} __attribute__((packed));


// eBPF map to store IP proto counters (tcp, udp, etc)
BPF_MAP_DEF(protocols) = {
    .map_type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 255,
};
BPF_MAP_ADD(protocols);


// XDP program //
SEC("xdp")
int packet_count(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  // Only IPv4 supported for this example
  struct ethhdr *ether = data;
  if (data + sizeof(*ether) > data_end) {
    return XDP_ABORTED;
  }
  if (ether->h_proto == 0x08U) {  // htons(ETH_P_IP) -> 0x08U
    data += sizeof(*ether);
    struct iphdr *ip = data;
    if (data + sizeof(*ip) > data_end) {
      return XDP_ABORTED;
    }
    // Increase counter in "protocols" eBPF map
    __u32 proto_index = ip->protocol;
    __u64 *counter = bpf_map_lookup_elem(&protocols, &proto_index);
    if (counter) {
      (*counter)++;
    }
  }

  return XDP_PASS;
}

char _license[] SEC("license") = "GPLv2";
