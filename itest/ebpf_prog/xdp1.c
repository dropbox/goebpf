// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

// Set of simple XDP programs for eBPF library integration tests

#include "bpf_helpers.h"

BPF_MAP_DEF(txcnt) = {
    .map_type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 100,
    .persistent_path = "/sys/fs/bpf/txcnt",
};
BPF_MAP_ADD(txcnt);

BPF_MAP_DEF(rxcnt) = {
    .map_type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u64),
    .value_size = sizeof(__u32),
    .max_entries = 50,
};
BPF_MAP_ADD(rxcnt);

BPF_MAP_DEF(match_maps_tx) = {
    .map_type = BPF_MAP_TYPE_ARRAY_OF_MAPS,
    .key_size = sizeof(__u32),
    .max_entries = 10,
    .inner_map_def = &txcnt,
};
BPF_MAP_ADD(match_maps_tx);

BPF_MAP_DEF(match_maps_rx) = {
    .map_type = BPF_MAP_TYPE_HASH_OF_MAPS,
    .key_size = sizeof(__u32),
    .max_entries = 20,
    .inner_map_def = &rxcnt,
    .persistent_path = "/sys/fs/bpf/match_maps_rx",
};
BPF_MAP_ADD(match_maps_rx);

BPF_MAP_DEF(array_map) = {
    .map_type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 10,
};
BPF_MAP_ADD(array_map);

BPF_MAP_DEF(perf_map) = {
    .map_type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .max_entries = 128,
};
BPF_MAP_ADD(perf_map);

#define PROG_CNT 2
BPF_MAP_DEF(programs) = {
    .map_type = BPF_MAP_TYPE_PROG_ARRAY,
    .max_entries = PROG_CNT,
};
BPF_MAP_ADD(programs);

SEC("xdp")
int xdp0(struct xdp_md *ctx)
{
  __u64 val = 1;

  bpf_map_lookup_elem(&array_map, &val);

  return XDP_PASS;
}

SEC("xdp")
int xdp1(struct xdp_md *ctx)
{
  __u64 val = 1;

  bpf_map_lookup_elem(&rxcnt, &val);

  return XDP_DROP;
}

SEC("xdp")
int xdp_head_meta2(struct xdp_md *ctx)
{
  __u64 *foo;
  void *data, *data_meta, *data_end;

  // Metadata test
  // Reserve space at the beginning of the packet for metadata
  int adj_len = 0 - (int)sizeof(*foo); // NOLINT
  bpf_xdp_adjust_meta(ctx, adj_len);
  data = (void *)(long)ctx->data;           // NOLINT
  data_meta = (void *)(long)ctx->data_meta; // NOLINT

  // Make kernel's verifier happy - check for boundaries
  if (data_meta + sizeof(*foo) <= data)
  {
    // Set some meta info before packet
    foo = data_meta;
    *foo = 112;
  }

  // Encap / decap test
  // Extend packet head by 4 bytes (encapsulation use case)
  bpf_xdp_adjust_head(ctx, adj_len);
  data = (void *)(long)ctx->data;         // NOLINT
  data_end = (void *)(long)ctx->data_end; // NOLINT

  // Make kernel's verifier happy - check for boundaries
  if (data + sizeof(*foo) <= data_end)
  {
    foo = data;
    *foo = 112;
  }

  return XDP_PASS;
}

SEC("xdp")
int xdp_root3(struct xdp_md *ctx)
{
#pragma unroll
  for (__u32 i = 0; i < PROG_CNT; i++)
  {
    bpf_tail_call(ctx, &programs, 0);
  }

  return XDP_DROP;
}

SEC("xdp")
int xdp_perf(struct xdp_md *ctx)
{
  // Simple program that just emits perf event with packet size.
  __u32 packet_size = ctx->data_end - ctx->data;

  bpf_perf_event_output(ctx, &perf_map, BPF_F_CURRENT_CPU, &packet_size, sizeof(packet_size));

  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
