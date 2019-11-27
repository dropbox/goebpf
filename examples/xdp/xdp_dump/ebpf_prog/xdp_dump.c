// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

// XDP dump is simple program that dumps IPv4 src/dst into perf event map.

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

// PerfEvent eBPF map
BPF_MAP_DEF(perfmap) = {
    .map_type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 128,
};
BPF_MAP_ADD(perfmap);


// PerfEvent item
struct packet_meta {
  __u32 src_ip, dst_ip;
  __u32 size;
};

// XDP program //
SEC("xdp")
int xdp_dump(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  // Ethernet header
  struct ethhdr *ether = data;
  if (data + sizeof(*ether) > data_end) {
    return XDP_ABORTED;
  }

  // Only IPv4 supported for this example
  if (ether->h_proto == 0x08U) {  // htons(ETH_P_IP) -> 0x08U
    data += sizeof(*ether);
    struct iphdr *ip = data;
    if (data + sizeof(*ip) > data_end) {
      return XDP_ABORTED;
    }

    // Copy data from original packet to meta data
    // (kernel's verified does not allow helpers to use packet directly)
    struct packet_meta m = {
      .src_ip = ip->saddr,
      .dst_ip = ip->daddr,
      .size = data_end - data,
    };
    bpf_perf_event_output(ctx, &perfmap, 0, &m, sizeof(m));
  }

  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
