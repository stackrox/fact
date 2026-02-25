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

/**
 * A map with a single entry, determining whether prefix filtering
 * should be done based on the `path_prefix` map.
 */
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, char);
  __uint(max_entries, 1);
} filter_by_prefix_map SEC(".maps");

/// Whether we should filter by path prefix or not.
__always_inline static bool filter_by_prefix() {
  unsigned int zero = 0;
  char* res = bpf_map_lookup_elem(&filter_by_prefix_map, &zero);

  // The NULL check is simply here to satisfy some verifiers, the result
  // will never actually be NULL.
  return res == NULL || *res != 0;
}

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __type(key, struct path_prefix_t);
  __type(value, char);
  __uint(max_entries, 256);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} path_prefix SEC(".maps");

/**
 * Helper struct holding a path in a buffer and its current length.
 *
 * The memory layout of this type is compliant with the requirements for
 * BPF_MAP_TYPE_LPM_TRIE lookups.
 *
 * We don't need access from userspace to this type, so we don't need
 * to define it in types.h.
 *
 * On some hooks the path might need to be handcrafted from multiple
 * sources, like a struct path* and a struct dentry*. In those cases the
 * verifier will think we can copy PATH_MAX bytes for each operation, so
 * the buffer here is (PATH_MAX * 2) in size to keep the verifier happy.
 */
struct bound_path_t {
  unsigned int len;
  char path[PATH_MAX * 2];
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, struct bound_path_t);
  __uint(max_entries, 2);
} bound_path_heap SEC(".maps");

typedef enum {
  BOUND_PATH_MAIN = 0,
  BOUND_PATH_ALTERNATE = 1,
} bound_path_buffer_t;

__always_inline static struct bound_path_t* get_bound_path(bound_path_buffer_t key) {
  return bpf_map_lookup_elem(&bound_path_heap, &key);
}

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 8 * 1024 * 1024);
} rb SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, inode_key_t);
  __type(value, inode_value_t);
  __uint(max_entries, 1024);
} inode_map SEC(".maps");

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
volatile const bool path_hooks_support_bpf_d_path;

// clang-format on
