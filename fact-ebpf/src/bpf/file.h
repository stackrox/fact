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

__always_inline static monitored_t is_monitored(const inode_key_t* inode, struct bound_path_t* path, const inode_key_t* parent) {
  const inode_value_t* volatile inode_value = inode_get(inode);
  const inode_value_t* volatile parent_value = inode_get(parent);

  monitored_t status = inode_is_monitored(inode_value, parent_value);
  if (status != NOT_MONITORED) {
    return status;
  }

  if (path_is_monitored(path)) {
    return MONITORED_BY_PATH;
  }

  return NOT_MONITORED;
}

// Check if a new directory should be tracked based on its parent and path.
// This is used during mkdir operations where the child inode doesn't exist yet.
__always_inline static monitored_t should_track_mkdir(inode_key_t parent_inode, struct bound_path_t* child_path) {
  const inode_value_t* volatile parent_value = inode_get(&parent_inode);

  if (parent_value != NULL) {
    return MONITORED_BY_PARENT;
  }

  if (path_is_monitored(child_path)) {
    return MONITORED_BY_PATH;
  }

  return NOT_MONITORED;
}
