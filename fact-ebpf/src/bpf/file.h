#pragma once

// clang-format off
#include "vmlinux.h"

#include "builtins.h"
#include "types.h"
#include "maps.h"
#include "inode.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
// clang-format on

__always_inline static bool path_is_monitored(struct bound_path_t* path) {
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

__always_inline static inode_monitored_t is_monitored(inode_key_t inode, struct bound_path_t* path, const inode_key_t* parent, inode_key_t** submit) {
  const inode_value_t* volatile inode_value = inode_get(&inode);
  const inode_value_t* volatile parent_value = inode_get(parent);

  inode_monitored_t status = inode_is_monitored(inode_value, parent_value);
  if (status != NOT_MONITORED) {
    return status;
  }

  *submit = NULL;
  if (path_is_monitored(path)) {
    return MONITORED;
  }

  return NOT_MONITORED;
}
