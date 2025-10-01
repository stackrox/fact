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

__always_inline static struct helper_t* get_helper() {
  unsigned int zero = 0;
  return bpf_map_lookup_elem(&helper_map, &zero);
}

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
 *
 * On some hooks the path might need to be handcrafted from multiple
 * sources, like a struct path* and a struct dentry*. In those cases the
 * verifier will think we can copy PATH_MAX bytes for each operation, so
 * the buffer here is (PATH_MAX * 2) in size to keep the verifier happy.
 */
struct path_cfg_helper_t {
  unsigned int len;
  char path[PATH_MAX * 2];
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, struct path_cfg_helper_t);
  __uint(max_entries, 1);
} path_prefix_helper SEC(".maps");

__always_inline static struct path_cfg_helper_t* get_prefix_helper() {
  unsigned int zero = 0;
  return bpf_map_lookup_elem(&path_prefix_helper, &zero);
}


struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
} rb SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, struct metrics_t);
  __uint(max_entries, 1);
} metrics SEC(".maps");

__always_inline static struct metrics_t* get_metrics() {
  unsigned int zero = 0;
  return bpf_map_lookup_elem(&metrics, &zero);
}

uint64_t host_mount_ns;

// clang-format on
