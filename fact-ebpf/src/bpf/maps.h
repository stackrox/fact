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
  __uint(max_entries, 1);
} bound_path_heap SEC(".maps");

__always_inline static struct bound_path_t* get_bound_path() {
  unsigned int zero = 0;
  return bpf_map_lookup_elem(&bound_path_heap, &zero);
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

struct {
  __uint(type, BPF_MAP_TYPE_INODE_STORAGE);
  __type(key, unsigned int);
  __type(value, char);
  __uint(max_entries, 0);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} ignored SEC(".maps");

__always_inline static void add_ignored(struct inode* inode) {
  bpf_inode_storage_get(&ignored, inode, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
}

__always_inline static bool is_ignored(struct inode* inode) {
  return bpf_inode_storage_get(&ignored, inode, NULL, 0) != NULL;
}

// clang-format on
