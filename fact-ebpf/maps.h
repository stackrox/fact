#pragma once

// clang-format off
#include "types.h"

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

struct helper_t {
  char buf[PATH_MAX * 2];
  const unsigned char* array[16];
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, struct helper_t);
  __uint(max_entries, 1);
} helper_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, struct path_cfg_t);
  __uint(max_entries, 64);
} paths_map SEC(".maps");


uint32_t paths_len;

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * sizeof(struct event_t));
} rb SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, struct metrics_t);
  __uint(max_entries, 1);
} metrics SEC(".maps");

uint64_t host_mount_ns;

// clang-format on
