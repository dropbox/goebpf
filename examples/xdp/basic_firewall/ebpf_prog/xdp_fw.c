// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

// Basic XDP firewall (IPv4 blacklisting)

#include "bpf_helpers.h"

#define MAX_RULES   16

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


BPF_MAP_DEF(matches) = {
    .map_type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = MAX_RULES,
};
BPF_MAP_ADD(matches);


BPF_MAP_DEF(blacklist) = {
    .map_type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(__u64),
    .value_size = sizeof(__u32),
    .max_entries = MAX_RULES,
};
BPF_MAP_ADD(blacklist);

// XDP program //
SEC("xdp")
int firewall(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  // Only IPv4 supported for this example
  struct ethhdr *ether = data;
  if (data + sizeof(*ether) > data_end) {
    // Malformed Ethernet header
    return XDP_ABORTED;
  }

  if (ether->h_proto != 0x08U) {  // htons(ETH_P_IP) -> 0x08U
    // Non IPv4 traffic
    return XDP_PASS;
  }

  data += sizeof(*ether);
  struct iphdr *ip = data;
  if (data + sizeof(*ip) > data_end) {
    // Malformed IPv4 header
    return XDP_ABORTED;
  }

  struct {
    __u32 prefixlen;
    __u32 saddr;
  } key;

  key.prefixlen = 32;
  key.saddr = ip->saddr;

  // Lookup SRC IP in blacklisted IPs
  __u64 *rule_idx = bpf_map_lookup_elem(&blacklist, &key);
  if (rule_idx) {
    // Matched, increase match counter for matched "rule"
    __u32 index = *(__u32*)rule_idx;  // make verifier happy
    __u64 *counter = bpf_map_lookup_elem(&matches, &index);
    if (counter) {
      (*counter)++;
    }
    return XDP_DROP;
  }

  return XDP_PASS;
}

char _license[] SEC("license") = "GPLv2";
