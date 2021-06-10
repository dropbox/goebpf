// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

// Set of simple TC programs for eBPF library integration tests

#include "bpf_helpers.h"


SEC("tc_cls")
int tc1(struct __sk_buff *skb)
{
  return BPF_OK;
}

SEC("tc_act")
int tc2(struct __sk_buff *skb)
{
  return BPF_DROP;
}

SEC("tc_act")
int tc3(struct __sk_buff *skb)
{
  return bpf_redirect(1, 0);
}

char _license[] SEC("license") = "GPL";
