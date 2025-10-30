#pragma once

// clang-format off
#include "vmlinux.h"

#include "types.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
// clang-format on

static __always_inline uint64_t metadata_fill(metadata_t* metadata, struct dentry* dentry) {
  struct inode* inode = BPF_CORE_READ(dentry, d_inode);
  if (inode == NULL) {
    return -1;
  }

  metadata->mode = BPF_CORE_READ(inode, i_mode);
  metadata->uid = BPF_CORE_READ(inode, i_uid.val);
  metadata->gid = BPF_CORE_READ(inode, i_gid.val);
  metadata->size = BPF_CORE_READ(inode, i_size);

  return 0;
}
