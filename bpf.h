/* Copyright (c) 2011-2014 PLUMgrid, http://plumgrid.com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */

// This is simplified version of linux/uapi/bpf.h

#ifndef _BPF_H__
#define _BPF_H__

#ifdef __linux__
#include <linux/types.h>
#include <linux/unistd.h>
#elif __APPLE__
// In order to be able to install package on Mac - define some types
#define __NR_bpf 515
typedef unsigned short __u16;  // NOLINT
typedef unsigned char __u8;
typedef unsigned int __u32;
typedef unsigned long long __u64;  // NOLINT
typedef __u64 __aligned_u64;
#else
#error "Arch not supported"
#endif

#define ptr_to_u64(ptr) ((__u64)(unsigned long)(ptr))

/* List of supported BPF syscall commands */
enum bpf_cmd {
  BPF_MAP_CREATE,
  BPF_MAP_LOOKUP_ELEM,
  BPF_MAP_UPDATE_ELEM,
  BPF_MAP_DELETE_ELEM,
  BPF_MAP_GET_NEXT_KEY,
  BPF_PROG_LOAD,
  BPF_OBJ_PIN,
  BPF_OBJ_GET,
  BPF_PROG_ATTACH,
  BPF_PROG_DETACH,
  BPF_PROG_TEST_RUN,
  BPF_PROG_GET_NEXT_ID,
  BPF_MAP_GET_NEXT_ID,
  BPF_PROG_GET_FD_BY_ID,
  BPF_MAP_GET_FD_BY_ID,
  BPF_OBJ_GET_INFO_BY_FD,
};

// Max length of eBPF object name
#define BPF_OBJ_NAME_LEN 16U

// Length of eBPF program tag size
#define BPF_TAG_SIZE 8U

// clang-format off
union bpf_attr {
    struct { /* anonymous struct used by BPF_MAP_CREATE command */
        __u32   map_type;   /* one of enum bpf_map_type */
        __u32   key_size;   /* size of key in bytes */
        __u32   value_size; /* size of value in bytes */
        __u32   max_entries;    /* max number of entries in a map */
        __u32   map_flags;  /* BPF_MAP_CREATE related
                     * flags defined above.
                     */
        __u32   inner_map_fd;   /* fd pointing to the inner map */
        __u32   numa_node;  /* numa node (effective only if
                     * BPF_F_NUMA_NODE is set).
                     */
        char    map_name[BPF_OBJ_NAME_LEN];
    };

    struct { /* anonymous struct used by BPF_MAP_*_ELEM commands */
        __u32       map_fd;
        __aligned_u64   key;
        union {
            __aligned_u64 value;
            __aligned_u64 next_key;
        };
        __u64       flags;
    };

    struct { /* anonymous struct used by BPF_PROG_LOAD command */
        __u32       prog_type;  /* one of enum bpf_prog_type */
        __u32       insn_cnt;
        __aligned_u64   insns;
        __aligned_u64   license;
        __u32       log_level;  /* verbosity level of verifier */
        __u32       log_size;   /* size of user buffer */
        __aligned_u64   log_buf;    /* user supplied buffer */
        __u32       kern_version;   /* checked when prog_type=kprobe */
        __u32       prog_flags;
        char        prog_name[BPF_OBJ_NAME_LEN];
        __u32       prog_ifindex;   /* ifindex of netdev to prep for */
    };

    struct { /* anonymous struct used by BPF_OBJ_* commands */
        __aligned_u64   pathname;
        __u32       bpf_fd;
        __u32       file_flags;
    };

    struct { /* anonymous struct used by BPF_PROG_ATTACH/DETACH commands */
        __u32       target_fd;  /* container object to attach to */
        __u32       attach_bpf_fd;  /* eBPF program to attach */
        __u32       attach_type;
        __u32       attach_flags;
    };

    struct { /* anonymous struct used by BPF_*_GET_*_ID */
        union {
            __u32       start_id;
            __u32       prog_id;
            __u32       map_id;
        };
        __u32       next_id;
        __u32       open_flags;
    };

    struct { /* anonymous struct used by BPF_OBJ_GET_INFO_BY_FD */
        __u32       bpf_fd;
        __u32       info_len;
        __aligned_u64   info;
    } info;
} __attribute__((aligned(8)));

struct bpf_prog_info {
    __u32 type;
    __u32 id;
    __u8  tag[BPF_TAG_SIZE];
    __u32 jited_prog_len;
    __u32 xlated_prog_len;
    __aligned_u64 jited_prog_insns;
    __aligned_u64 xlated_prog_insns;
    __u64 load_time;    // ns since boottime
    __u32 created_by_uid;
    __u32 nr_map_ids;
    __aligned_u64 map_ids;
    char name[BPF_OBJ_NAME_LEN];
    __u32 ifindex;
    __u32 gpl_compatible:1;
    __u64 netns_dev;
    __u64 netns_ino;
    __u32 nr_jited_ksyms;
    __u32 nr_jited_func_lens;
    __aligned_u64 jited_ksyms;
    __aligned_u64 jited_func_lens;
} __attribute__((aligned(8)));
// clang-format on

#endif /* _BPF_H__ */
