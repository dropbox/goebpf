// Copyright (c) 2022 Dropbox, Inc.
// Based on the example by Konstantin Belyalov:
// https://github.com/dropbox/goebpf/blob/master/examples/xdp/packet_counter/ebpf_prog/xdp.c

#ifndef GO_EBPF
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#include <linux/byteorder/little_endian.h>
#else
#include <linux/byteorder/big_endian.h>
#endif
#endif

#ifdef GO_EBPF
// if compiling for goebpf, use our local bpf_helpers.h
#include "bpf_helpers.h"
#else
// if compiling to be attached with iproute2
//   (`tc filter add ... bpf obj tc.o ...`), pull these headers
// in from the system
#include <asm/types.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <iproute2/bpf_elf.h>
#include <sys/cdefs.h>
#endif

#include <linux/pkt_cls.h>

#define HASH_FLAG_DIR_INGRESS  0
#define HASH_FLAG_DIR_EGRESS   (1 << 0)
#define HASH_FLAG_UNIT_PACKETS 0
#define HASH_FLAG_UNIT_BYTES   (1 << 1)

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

// BPF_MAP_DEF is outdated in currently shipping linux-api-headers as of
// 08/2022 :/
// Latest libbpf requires maps defined in BTF, while goebpf uses the old
// maps section format, so we support both here.
#undef BPF_MAP_DEF

#ifdef GO_EBPF
#define BPF_MAP_DEF(_name, _type, _key_size, _value_size, _max_entries) \
	struct bpf_map_def SEC("maps") _name = {                            \
		.map_type = _type,                                              \
		.key_size = _key_size,                                          \
		.value_size = _value_size,                                      \
		.max_entries = _max_entries,                                    \
	}

#else
#define BPF_MAP_DEF(_name, _type, _key_size, _value_size, _max_entries) \
	struct {                                                            \
		__u32 (*type)[BPF_MAP_TYPE_PERCPU_ARRAY];                       \
		__u32 (*key_size)[sizeof(__u32)];                               \
		__u32 (*value_size)[sizeof(__u64)];                             \
		__u32 (*max_entries)[255];                                      \
	} _name SEC(".maps");
#endif
