// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

// BPF helpers
// Set of defines / prototypes to use from eBPF programs as well as from regular
// linux/mac "cross" compilation.

#ifndef __BPF_HELPERS_H
#define __BPF_HELPERS_H

// Standard types.
// Due to tooons of dependencies in standard linux kernel headers
// Define types explicitly.
typedef unsigned short __u16;  // NOLINT
typedef unsigned char __u8;
typedef unsigned int __u32;
typedef unsigned long long __u64;

// BPF map types
enum bpf_map_type {
  BPF_MAP_TYPE_UNSPEC = 0,
  BPF_MAP_TYPE_HASH,
  BPF_MAP_TYPE_ARRAY,
  BPF_MAP_TYPE_PROG_ARRAY,
  BPF_MAP_TYPE_PERF_EVENT_ARRAY,
  BPF_MAP_TYPE_PERCPU_HASH,
  BPF_MAP_TYPE_PERCPU_ARRAY,
  BPF_MAP_TYPE_STACK_TRACE,
  BPF_MAP_TYPE_CGROUP_ARRAY,
  BPF_MAP_TYPE_LRU_HASH,
  BPF_MAP_TYPE_LRU_PERCPU_HASH,
  BPF_MAP_TYPE_LPM_TRIE,
  BPF_MAP_TYPE_ARRAY_OF_MAPS,
  BPF_MAP_TYPE_HASH_OF_MAPS,
};

// bpf_map_update() flags
#define BPF_ANY 0     /* create new element or update existing */
#define BPF_NOEXIST 1 /* create new element if it didn't exist */
#define BPF_EXIST 2   /* update existing element */

// A helper structure used by eBPF C program
// to describe map attributes to BPF program loader
struct bpf_map_def {
  __u32 map_type;
  __u32 key_size;
  __u32 value_size;
  __u32 max_entries;
  __u32 map_flags;
  // Array/Hash of maps use case: pointer to inner map template
  void *inner_map_def;
  // Define this to make map system wide ("object pinning")
  // path could be anything, like '/sys/fs/bpf/foo'
  // WARN: You must have BPF filesystem mounted on provided location
  const char *persistent_path;
};

#define BPF_MAP_DEF_SIZE sizeof(struct bpf_map_def)
#define BPF_MAP_OFFSET_PERSISTENT offsetof(struct bpf_map_def, persistent_path)
#define BPF_MAP_OFFSET_INNER_MAP offsetof(struct bpf_map_def, inner_map_def)

// XDP related constants
enum xdp_action {
  XDP_ABORTED = 0,
  XDP_DROP,
  XDP_PASS,
  XDP_TX,
  XDP_REDIRECT,
};

#define bpf_likely(X) __builtin_expect(!!(X), 1)
#define bpf_unlikely(X) __builtin_expect(!!(X), 0)
#define UNUSED __attribute__((unused))

// In order to cross compile BPF program for BPF / Linux / Mac
// we need to define platform specific things like:
// 1. Custom (non kernel) implementation for bpf_map_* functions
// 2. For BPF we need to put programs into special sections, but, for
//    regular linux target (mostly for tests) we don't.
// 3. BPF does not support function calls, so __always_inline__ is must have.
//    However, for testing it doesn't make sense.
// 4. Debug prints - for BPF it is done by calling helper, for linux just
// regular printf()
#ifdef __BPF__

// Clang for eBPF missed static_assert declaration because programs are C, not
// CPP
#define static_assert _Static_assert

// Helper macro to place programs, maps, license in
// different sections in ELF file.
#define SEC(NAME) __attribute__((section(NAME), used))

// eBPF does not support functions (yet), so, all functions MUST be inlined.
// Starting from kernel 4.16 it is not required to always inline functions
// since support has been added
#define INLINE __attribute__((__always_inline__))

// XDP metadata - basically data packet
// P.S. for some reason XDP programs uses 32bit pointers
struct xdp_md {
  __u32 data;
  __u32 data_end;
  __u32 data_meta;
};

// BPF helper functions supported on linux kernel 4.15+
// clang-format off
#define __BPF_FUNC_MAPPER(FN)       \
    FN(unspec),                     \
    FN(map_lookup_elem),            \
    FN(map_update_elem),            \
    FN(map_delete_elem),            \
    FN(probe_read),                 \
    FN(ktime_get_ns),               \
    FN(trace_printk),               \
    FN(get_prandom_u32),            \
    FN(get_smp_processor_id),       \
    FN(skb_store_bytes),            \
    FN(l3_csum_replace),            \
    FN(l4_csum_replace),            \
    FN(tail_call),                  \
    FN(clone_redirect),             \
    FN(get_current_pid_tgid),       \
    FN(get_current_uid_gid),        \
    FN(get_current_comm),           \
    FN(get_cgroup_classid),         \
    FN(skb_vlan_push),              \
    FN(skb_vlan_pop),               \
    FN(skb_get_tunnel_key),         \
    FN(skb_set_tunnel_key),         \
    FN(perf_event_read),            \
    FN(redirect),                   \
    FN(get_route_realm),            \
    FN(perf_event_output),          \
    FN(skb_load_bytes),             \
    FN(get_stackid),                \
    FN(csum_diff),                  \
    FN(skb_get_tunnel_opt),         \
    FN(skb_set_tunnel_opt),         \
    FN(skb_change_proto),           \
    FN(skb_change_type),            \
    FN(skb_under_cgroup),           \
    FN(get_hash_recalc),            \
    FN(get_current_task),           \
    FN(probe_write_user),           \
    FN(current_task_under_cgroup),  \
    FN(skb_change_tail),            \
    FN(skb_pull_data),              \
    FN(csum_update),                \
    FN(set_hash_invalid),           \
    FN(get_numa_node_id),           \
    FN(skb_change_head),            \
    FN(xdp_adjust_head),            \
    FN(probe_read_str),             \
    FN(get_socket_cookie),          \
    FN(get_socket_uid),             \
    FN(set_hash),                   \
    FN(setsockopt),                 \
    FN(skb_adjust_room),            \
    FN(redirect_map),               \
    FN(sk_redirect_map),            \
    FN(sock_map_update),            \
    FN(xdp_adjust_meta),            \
    FN(perf_event_read_value),      \
    FN(perf_prog_read_value),       \
    FN(getsockopt),

#define __BPF_ENUM_FN(x) BPF_FUNC_ ## x
enum bpf_func_id {
    __BPF_FUNC_MAPPER(__BPF_ENUM_FN)
    __BPF_FUNC_MAX_ID,
};
#undef __BPF_ENUM_FN
// clang-format on

// BPF helper functions - this construction looks complicated, but actually
// it explained to just:
//      static void* bpf_map_lookup_elem(void *map, void *key) = 1
// In other words bpf_map_lookup_elem points to memory address 0x1 - which is
// BPF function number 1.
// More details about helper functions at: http://docs.cilium.io/en/v1.1/bpf/
// Search for "Helper Functions"
// clang-format off

// Lookup bpf map element by key.
// Return: Map value or NULL
static void *(*bpf_map_lookup_elem)(const void *map, const void *key) = (void *)  // NOLINT
    BPF_FUNC_map_lookup_elem;

// Update bpf map element by key to value
// Return: 0 on success or negative error
static int (*bpf_map_update_elem)(const void *map, const void *key,
                                  const void *value, __u64 flags) = (void *)  // NOLINT
    BPF_FUNC_map_update_elem;

// Delete element. Actually applicable on HASH maps
// Return: 0 on success or negative error
static int (*bpf_map_delete_elem)(const void *map, void *key) = (void *)  // NOLINT
    BPF_FUNC_map_delete_elem;

// Like printf() for BPF
// Return: length of buffer written or negative error
static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) = (void *)  // NOLINT
    BPF_FUNC_trace_printk;

// Jump into another BPF program
//     prog_array_map: pointer to map which type is BPF_MAP_TYPE_PROG_ARRAY
//     index: 32-bit index inside array that selects specific program to run
// Return: 0 on success or negative error
 static void (*bpf_tail_call)(const void *ctx, void *map, int index) = (void *)  // NOLINT
    BPF_FUNC_tail_call;

// Adjust the xdp_md.data by delta
//     ctx: pointer to xdp_md
//     delta: An positive/negative integer to be added to ctx.data
// Return: 0 on success or negative on error
static int (*bpf_xdp_adjust_head)(const void *ctx, int delta) = (void *) // NOLINT
    BPF_FUNC_xdp_adjust_head;

// Adjust the xdp_md.data_meta by delta
//     ctx: pointer to xdp_md
//     delta: An positive/negative integer to be added to ctx.data_meta
// Return: 0 on success or negative on error
static int (*bpf_xdp_adjust_meta)(const void *ctx, int delta) = (void *) // NOLINT
    BPF_FUNC_xdp_adjust_meta;
// clang-format on

// printk() - kernel trace mechanism, like printf()
// To get trace (debug) messages:
// - Add #define DEBUG into your eBPF program before includes
// - $ sudo cat /sys/kernel/debug/tracing/trace
#ifdef DEBUG
#define bpf_printk(fmt, ...)                                   \
  ({                                                           \
    char ____fmt[] = fmt;                                      \
    bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
  })
#else
#define bpf_printk(fmt, ...)
#endif

// Since BPF programs cannot perform any function calls other than
// those to BPF helpers, common library code needs to be implemented
// as inline functions. In addition, also LLVM provides some built-ins
// that can be used for constant sizes.
#define memset(dest, chr, n) __builtin_memset((dest), (chr), (n))
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#define memmove(dest, src, n) __builtin_memmove((dest), (src), (n))

// Do not allow use printf()
#define printf(fmt, ...) do_not_use_printf_use_bpf_printk

// Macro to define BPF Map
#define BPF_MAP_DEF(name) struct bpf_map_def SEC("maps") name
#define BPF_MAP_ADD(x)

///// end of __BPF__ /////

#else

//// All other platforms ////

// SEC() is useless for non eBPF - so just dummy
#define SEC(NAME)
// Functions must be inlined only for eBPF, so don't enforce it for *nix/mac.
// Also disable "unused function" warning -
// since eBPF programs define functions mostly in headers.
#define INLINE static __attribute__((unused))

// Disable warnings for "pragma unroll(all)"
#pragma GCC diagnostic ignored "-Wunknown-pragmas"

#include <assert.h>
#include <stdio.h>
#include <sys/queue.h>
#include <string.h>

// XDP metadata - defined twice because of real eBPF uses 32 bit pointers
// which are not acceptable for cross platform compilation.
struct xdp_md {
  void *data;
  void *data_end;
  void *data_meta;
};

// Mock BPF map support:
// In order to automatically find all defined BPF maps from GO program we need
// to
// maintain linked list of maps (to be able to iterate and create them all)
// This could be easily and nicely done using __attribute__ ((constructor))
// Which is logically close to func init() int GO.
struct __create_map_def {
  const char *name;
  void *map_data;  // Mock version only: holds head to single linked list of map
                   // items
  struct bpf_map_def *map_def;
  SLIST_ENTRY(__create_map_def) next;
};

// Declaration only. Definition held in mock_map package.
SLIST_HEAD(__maps_head_def, __create_map_def);
extern struct __maps_head_def *__maps_head;

#define BPF_MAP_DEF(x) static struct bpf_map_def x

#define BPF_MAP_ADD(x)                                          \
  static __attribute__((constructor)) void __bpf_map_##x() {    \
    static struct __create_map_def __bpf_map_entry_##x;         \
    __bpf_map_entry_##x.name = #x;                              \
    __bpf_map_entry_##x.map_data = NULL;                        \
    __bpf_map_entry_##x.map_def = &x;                           \
    SLIST_INSERT_HEAD(__maps_head, &__bpf_map_entry_##x, next); \
  }

// BPF helper prototypes - definition is up to mac/linux host program
void *bpf_map_lookup_elem(const void *map, const void *key);
int bpf_map_update_elem(const void *map, const void *key, const void *value,
                        __u64 flags);
int bpf_map_delete_elem(const void *map, const void *key);

// bpf_printk() is just printf()
#define bpf_printk(fmt, ...)  \
  printf(fmt, ##__VA_ARGS__); \
  fflush(stdout);

// bpf_tail_call() is nothing: only relevant for BPF arch
#define bpf_tail_call(ctx, map, index)

// adjust_meta / ajdust_header are simple functions to move pointer

UNUSED static int bpf_xdp_adjust_meta(struct xdp_md *ctx, int offset) {
  // For unittests only - function returns error if data_meta points to data_end
  // which never the case in real world
  if (ctx->data_meta == ctx->data_end) {
    return 1;
  }
  ctx->data_meta = (__u8 *)ctx->data_meta + offset;  // NOLINT

  return 0;
}

UNUSED static int bpf_xdp_adjust_head(struct xdp_md *ctx, int offset) {
  ctx->data = (__u8 *)ctx->data + offset;  // NOLINT

  return 0;
}

#endif  // of other than __BPF__

// Finally make sure that all types have expected size regardless of platform
static_assert(sizeof(__u8) == 1, "wrong_u8_size");
static_assert(sizeof(__u16) == 2, "wrong_u16_size");
static_assert(sizeof(__u32) == 4, "wrong_u32_size");
static_assert(sizeof(__u64) == 8, "wrong_u64_size");

#endif
