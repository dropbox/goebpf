// Copyright (c) 2020 Dropbox, Inc.
// Full license can be found in the LICENSE file.


// uncomment this to get prints at /sys/kernel/debug/tracing/trace
// #define DEBUG

#define AF_INET		2	/* Internet IP Protocol 	*/
#define ETH_ALEN    6


#include <bpf_helpers.h>


// Ethernet header
// #include <linux/if_ether.h>
struct ethhdr {
  __u8 h_dest[6];
  __u8 h_source[6];
  __u16 h_proto;
} __attribute__((packed));

// IPv4 header
// #include <linux/ip.h>
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

/* XDP enabled TX ports for redirect map */
BPF_MAP_DEF(if_redirect) = {
    .map_type = BPF_MAP_TYPE_DEVMAP,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 64,
};
BPF_MAP_ADD(if_redirect);

/* This program matches ICMP packets (IPPROTO = 0X01) and redirects it back to the sender.
   Using bpf_fib_lookup, we use the kernel routing table to perform a FIB lookup and send
   packet back to whoever sent that to us (rewriting ip and mac addresses fields). 
   This means that the XDP code can essentially route packets, provided that the kernel has
   the forwarding information. 
   For more info on Linux and routing lookup: https://vincent.bernat.ch/en/blog/2017-ipv4-route-lookup-linux
*/
SEC("xdp")
int xdp_test(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth_header;
    struct iphdr *ip_header;
    eth_header = data;
    if ((void *)eth_header + sizeof(*eth_header) > data_end) {
        return XDP_PASS;
    }

    __u16 h_proto = eth_header->h_proto;

    /* anything that is not IPv4 (including ARP) goes up to the kernel */
    if (h_proto != 0x08U) {  // htons(ETH_P_IP) -> 0x08U
        return XDP_PASS;
    }
    ip_header = data + sizeof(*eth_header);
    if ((void *)ip_header + sizeof(*ip_header) > data_end) {
        return XDP_PASS;
    }

    if (ip_header->protocol != 0x01) { // IPPROTO_ICMP = 1
        return XDP_PASS;
    }

    // if icmp, we send it back to the gateway
    // Create bpf_fib_lookup to help us route the packet
    struct bpf_fib_lookup fib_params;
    
    // fill struct with zeroes, so we are sure no data is missing
    __builtin_memset(&fib_params, 0, sizeof(fib_params));

    fib_params.family	= AF_INET;
    // use daddr as source in the lookup, so we refleect packet back (as if it wcame from us)
    fib_params.ipv4_src	= ip_header->daddr;
    // opposite here, the destination is the source of the icmp packet..remote end
    fib_params.ipv4_dst	= ip_header->saddr;
    fib_params.ifindex = ctx->ingress_ifindex;

    bpf_printk("doing route lookup dst: %d\n", fib_params.ipv4_dst);
    int rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
    if ((rc != BPF_FIB_LKUP_RET_SUCCESS) && (rc != BPF_FIB_LKUP_RET_NO_NEIGH)) {
        bpf_printk("Dropping packet\n");
        return XDP_DROP;
    } else if (rc == BPF_FIB_LKUP_RET_NO_NEIGH) {
        // here we should let packet pass so we resolve arp.
        bpf_printk("Passing packet, lookup returned %d\n", BPF_FIB_LKUP_RET_NO_NEIGH);
        return XDP_PASS;
    }
    bpf_printk("route lookup success, ifindex: %d\n", fib_params.ifindex);
    bpf_printk("mac to use as dst is: %lu\n", fib_params.dmac);

    // Swap src with dst ip
    __u32 oldipdst = ip_header->daddr;
    ip_header->daddr = ip_header->saddr;
    ip_header->saddr = oldipdst;

    // copy resulting dmac/smac from the fib lookup
    memcpy(eth_header->h_dest, fib_params.dmac, ETH_ALEN);
    memcpy(eth_header->h_source, fib_params.smac, ETH_ALEN);

    // redirect packet to the resulting ifindex
    return bpf_redirect_map(&if_redirect, fib_params.ifindex, 0);

}

char _license[] SEC("license") = "GPL";