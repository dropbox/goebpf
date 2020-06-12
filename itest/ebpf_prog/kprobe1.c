// Copyright (c) 2020 Dropbox, Inc.
// Full license can be found in the LICENSE file.

// Set of simple kprobe programs for eBPF library integration tests

#include "bpf_helpers.h"

BPF_MAP_DEF(perf_map) = {
    .map_type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .max_entries = 128,
};
BPF_MAP_ADD(perf_map);

SEC("kprobe/guess_execve")
int kprobe0(struct pt_regs *ctx) {
  char comm[32];
  bpf_get_current_comm(comm, sizeof(comm));
  bpf_perf_event_output(ctx, &perf_map, BPF_F_CURRENT_CPU, comm, sizeof(comm));
  return 0;
}

SEC("kretprobe/guess_execve")
int kprobe1(struct pt_regs *ctx) {
  char comm[32];
  bpf_get_current_comm(comm, sizeof(comm));
  bpf_perf_event_output(ctx, &perf_map, BPF_F_CURRENT_CPU, comm, sizeof(comm));
  return 0;
}

char _license[] SEC("license") = "GPL";
