// Copyright (c) 2022 Dropbox, Inc.
// Based on the example by Konstantin Belyalov:
// https://github.com/dropbox/goebpf/blob/master/examples/xdp/packet_counter/ebpf_prog/xdp.c
#include "tc.h"

// eBPF map to store IP metric counters
BPF_MAP_DEF(metrics, BPF_MAP_TYPE_PERCPU_ARRAY, sizeof(__u32), sizeof(__u64), 255);

static __always_inline int account_data(struct __sk_buff *skb, __u32 hashidx)
{
  void *data_end = (void *)(long)skb->data_end;
  void *data = (void *)(long)skb->data;
  // Only IPv4 supported for now
  struct ethhdr *ether = data;
  if (data + sizeof(*ether) > data_end) {
    return TC_ACT_OK;
  }
  if (ether->h_proto == 0x08U) {  // htons(ETH_P_IP) -> 0x08U
    data += sizeof(*ether);
    struct iphdr *ip = data;
    if (data + sizeof(*ip) > data_end) {
      return TC_ACT_OK;
    }
    if (ip->version != 4) {
      return TC_ACT_OK;
    }
    // Increment packet count
    __u64 *counter = bpf_map_lookup_elem(&metrics, &hashidx);
    if (counter) {
      __sync_fetch_and_add(counter, 1);
    }
    // Increment total bytes
    hashidx |= HASH_FLAG_UNIT_BYTES;
    counter = bpf_map_lookup_elem(&metrics, &hashidx);
    if (counter) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
      // byte swap tot_len to LE before adding
      __sync_fetch_and_add(counter,
        ((ip->tot_len << 8) & 0xFF00) | (ip->tot_len >> 8));
#else
      __sync_fetch_and_add(counter, ip->tot_len);
#endif
    }
  }
  return TC_ACT_OK;
}
// TC program //
SEC("tc_cls")
int tc_ingress(struct __sk_buff *skb) {
  return account_data(skb, HASH_FLAG_DIR_INGRESS);
}
SEC("tc_cls")
int tc_egress(struct __sk_buff *skb) {
  return account_data(skb, HASH_FLAG_DIR_EGRESS);
}
char _license[] SEC("license") = "GPLv2";
