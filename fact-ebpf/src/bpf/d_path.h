#pragma once

// clang-format off
#include "vmlinux.h"

#include "maps.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
// clang-format on

/**
 * PATH_MAX is defined in the kernel as 4096 which translates to 0x1000.
 * This define gives as an easy way to clamp path lengths
 */
#define PATH_MAX_MASK (PATH_MAX - 1)

/**
 * Helper for keeping the verifier happy.
 *
 * Whenever a path is interacted with in a buffer, this macro can be
 * used to convince the verifier no more than PATH_MAX bytes will be
 * accessed.
 */
#define PATH_LEN_CLAMP(len) ((len) & PATH_MAX_MASK)

struct d_path_ctx {
  struct helper_t* helper;
  struct path* root;
  struct mount* mnt;
  struct dentry* dentry;
  int offset;
  int buflen;
  bool success;
};

__always_inline static long d_path(struct path* path, char* buf, int buflen, bool use_bpf_helper) {
  return bpf_d_path(path, buf, buflen);
}
