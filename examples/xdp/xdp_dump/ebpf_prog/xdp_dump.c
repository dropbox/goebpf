// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

// XDP dump is simple program that dumps new IPv4 TCP connections through perf events.

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

// TCP header
struct tcphdr {
  __u16 source;
  __u16 dest;
  __u32 seq;
  __u32 ack_seq;
  union {
    struct {
      // Field order has been converted LittleEndiand -> BigEndian
      // in order to simplify flag checking (no need to ntohs())
      __u16 ns : 1,
      reserved : 3,
      doff : 4,
      fin : 1,
      syn : 1,
      rst : 1,
      psh : 1,
      ack : 1,
      urg : 1,
      ece : 1,
      cwr : 1;
    };
  };
  __u16 window;
  __u16 check;
  __u16 urg_ptr;
};

// PerfEvent eBPF map
BPF_MAP_DEF(perfmap) = {
    .map_type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .max_entries = 128,
};
BPF_MAP_ADD(perfmap);


// PerfEvent item
struct perf_event_item {
  __u32 src_ip, dst_ip;
  __u16 src_port, dst_port;
};
_Static_assert(sizeof(struct perf_event_item) == 12, "wrong size of perf_event_item");

// XDP program //
SEC("xdp")
int xdp_dump(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  __u64 packet_size = data_end - data;

  // L2
  struct ethhdr *ether = data;
  if (data + sizeof(*ether) > data_end) {
    return XDP_ABORTED;
  }

  // L3
  if (ether->h_proto != 0x08) {  // htons(ETH_P_IP) -> 0x08
    // Non IPv4
    return XDP_PASS;
  }
  data += sizeof(*ether);
  struct iphdr *ip = data;
  if (data + sizeof(*ip) > data_end) {
    return XDP_ABORTED;
  }

  // L4
  if (ip->protocol != 0x06) {  // IPPROTO_TCP -> 6
    // Non TCP
    return XDP_PASS;
  }
  data += ip->ihl * 4;
  struct tcphdr *tcp = data;
  if (data + sizeof(*tcp) > data_end) {
    return XDP_ABORTED;
  }

  // Emit perf event for every TCP SYN packet
  if (tcp->syn) {
    struct perf_event_item evt = {
      .src_ip = ip->saddr,
      .dst_ip = ip->daddr,
      .src_port = tcp->source,
      .dst_port = tcp->dest,
    };
    // flags for bpf_perf_event_output() actually contain 2 parts (each 32bit long):
    //
    // bits 0-31: either
    // - Just index in eBPF map
    // or
    // - "BPF_F_CURRENT_CPU" kernel will use current CPU_ID as eBPF map index
    //
    // bits 32-63: may be used to tell kernel to amend first N bytes
    // of original packet (ctx) to the end of the data.

    // So total perf event length will be sizeof(evt) + packet_size
    __u64 flags = BPF_F_CURRENT_CPU | (packet_size << 32);
    bpf_perf_event_output(ctx, &perfmap, flags, &evt, sizeof(evt));
  }

  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
