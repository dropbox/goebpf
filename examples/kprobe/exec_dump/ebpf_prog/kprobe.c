// Copyright (c) 2020 Dropbox, Inc.
// Full license can be found in the LICENSE file.

#include "bpf_helpers.h"

#define BUFSIZE_PADDED (2 << 13)
#define BUFSIZE ((BUFSIZE_PADDED - 1) >> 1)
#define MAX_ARGLEN 256
#define MAX_ARGS 20
#define NARGS 6
#define NULL ((void *)0)
#define TASK_COMM_LEN 32

typedef unsigned long args_t;

typedef struct event {
  __u64 ktime_ns;
  __u32 pid;
  __u32 uid;
  __u32 gid;
  __s32 type;
  char comm[TASK_COMM_LEN];
} event_t;

typedef struct buf {
  __u32 off;
  __u8 data[BUFSIZE_PADDED];
} buf_t;

BPF_MAP_DEF(events) = {
    .map_type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .max_entries = 1024,
};
BPF_MAP_ADD(events);

BPF_MAP_DEF(buffer) = {
    .map_type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = BUFSIZE_PADDED,
    .max_entries = 1,
};
BPF_MAP_ADD(buffer);

static inline void get_args(struct pt_regs *ctx, unsigned long *args) {
  // if registers are valid then use them directly (kernel version < 4.17)
  if (ctx->orig_ax || ctx->bx || ctx->cx || ctx->dx) {
    args[0] = PT_REGS_PARM1(ctx);
    args[1] = PT_REGS_PARM2(ctx);
    args[2] = PT_REGS_PARM3(ctx);
    args[3] = PT_REGS_PARM4(ctx);
    args[4] = PT_REGS_PARM5(ctx);
    args[5] = PT_REGS_PARM6(ctx);
  } else {
    // otherwise it's a later kernel version so load register values from
    // ctx->di.
    struct pt_regs *regs = (struct pt_regs *)ctx->di;
    bpf_probe_read(&args[0], sizeof(*args), &regs->di);
    bpf_probe_read(&args[1], sizeof(*args), &regs->si);
    bpf_probe_read(&args[2], sizeof(*args), &regs->dx);
    bpf_probe_read(&args[3], sizeof(*args), &regs->r10);
    bpf_probe_read(&args[4], sizeof(*args), &regs->r8);
    bpf_probe_read(&args[5], sizeof(*args), &regs->r9);
  }
}

static inline buf_t *get_buf() {
  __u32 key = 0;
  return (buf_t *)bpf_map_lookup_elem(&buffer, &key);
}

static inline int buf_perf_output(struct pt_regs *ctx) {
  buf_t *buf = get_buf();
  if (buf == NULL) {
    return -1;
  }
  int size = buf->off & BUFSIZE;
  buf->off = 0;
  return bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                               (void *)buf->data, size);
}

static inline int buf_write(buf_t *buf, void *ptr, int size) {
  if (buf->off >= BUFSIZE) {
    return 0;
  }

  if (bpf_probe_read(&(buf->data[buf->off]), size, ptr) == 0) {
    buf->off += size;
    return size;
  }

  return -1;
}

static inline int buf_strcat(buf_t *buf, void *ptr) {
  if (buf->off >= BUFSIZE) {
    return 0;
  }

  int n = bpf_probe_read_str(&(buf->data[buf->off]), MAX_ARGLEN, ptr);
  if (n > 0) {
    buf->off += n;
  }

  return n;
}

static inline int buf_strcat_argp(buf_t *buf, void *ptr) {
  const char *argp = NULL;
  bpf_probe_read(&argp, sizeof(argp), ptr);
  if (argp) {
    return buf_strcat(buf, (void *)(argp));
  }
  return 0;
}

static inline int buf_strcat_argv(buf_t *buf, void **ptr) {
#pragma unroll
  for (int i = 0; i < MAX_ARGS; i++) {
    if (buf_strcat_argp(buf, &ptr[i]) == 0) {
      return 0;
    }
  }
  return 0;
}

SEC("kprobe/guess_execve")
int execve_entry(struct pt_regs *ctx) {
  buf_t *buf = get_buf();
  if (buf == NULL) {
    return 0;
  }

  args_t args[NARGS] = {};
  get_args(ctx, args);

  event_t e = {0};
  e.ktime_ns = bpf_ktime_get_ns();
  e.pid = bpf_get_current_pid_tgid() >> 32;
  e.uid = bpf_get_current_uid_gid() >> 32;
  e.gid = bpf_get_current_uid_gid();
  bpf_get_current_comm(&e.comm, sizeof(e.comm));

  buf_write(buf, (void *)&e, sizeof(e));
  buf_strcat(buf, (void *)args[0]);
  buf_strcat_argv(buf, (void *)args[1]);
  buf_perf_output(ctx);

  return 0;
}

char _license[] SEC("license") = "GPL";
