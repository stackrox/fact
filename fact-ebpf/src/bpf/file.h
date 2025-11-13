#pragma once

// clang-format off
#include "vmlinux.h"

#include "bound_path.h"
#include "builtins.h"
#include "d_path.h"
#include "types.h"
#include "maps.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
// clang-format on

__always_inline static char* get_host_path(char buf[PATH_MAX * 2], struct dentry* d) {
  int offset = PATH_MAX - 1;
  buf[PATH_MAX - 1] = '\0';

  for (int i = 0; i < 16 && offset > 0; i++) {
    struct qstr d_name;
    BPF_CORE_READ_INTO(&d_name, d, d_name);
    if (d_name.name == NULL) {
      break;
    }

    int len = d_name.len;
    if (len <= 0 || len >= PATH_MAX) {
      return NULL;
    }

    offset -= len;
    if (offset <= 0) {
      return NULL;
    }

    if (bpf_probe_read_kernel(&buf[offset], len, d_name.name) != 0) {
      return NULL;
    }

    if (len == 1 && buf[offset] == '/') {
      // Reached the root
      offset++;
      break;
    }

    offset--;
    buf[offset] = '/';

    struct dentry* parent = BPF_CORE_READ(d, d_parent);
    // if we reached the root
    if (parent == NULL || d == parent) {
      break;
    }
    d = parent;
  }

  return &buf[offset];
}

__always_inline static bool is_monitored(struct bound_path_t* path) {
  if (!filter_by_prefix()) {
    // no path configured, allow all
    return true;
  }

  // Backup bytes length and restore it before exiting
  unsigned int len = path->len;

  if (path->len > LPM_SIZE_MAX) {
    path->len = LPM_SIZE_MAX;
  }
  // for LPM maps, the length is the total number of bits
  path->len = path->len * 8;

  bool res = bpf_map_lookup_elem(&path_prefix, path) != NULL;
  path->len = len;
  return res;
}
