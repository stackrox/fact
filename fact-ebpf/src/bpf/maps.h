#pragma once

// clang-format off
#include "types.h"

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

/**
 * Helper struct with buffers for various operations
 */
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

bool filter_by_prefix; /// Whether we should filter by path prefix or not.
struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __type(key, struct path_prefix_t);
  __type(value, char);
  __uint(max_entries, 256);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} path_prefix SEC(".maps");

/**
 * Helper struct for LPM filtering.
 *
 * This struct has a buffer big enough to hold a full path while also
 * having the memory layout required by the BPF_MAP_TYPE_LPM_TRIE map.
 *
 * We don't need access from userspace to this type, so we don't need
 * to define it in types.h.
 */
struct path_cfg_helper_t {
  unsigned int bit_len;
  char path[PATH_MAX * 2];
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, struct path_cfg_helper_t);
  __uint(max_entries, 1);
} path_prefix_helper SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
} rb SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, struct metrics_t);
  __uint(max_entries, 1);
} metrics SEC(".maps");

uint64_t host_mount_ns;

// clang-format on
