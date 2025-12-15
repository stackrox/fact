#pragma once

// clang-format off
#include "vmlinux.h"

#include "builtins.h"
#include "types.h"
#include "maps.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
// clang-format on

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
