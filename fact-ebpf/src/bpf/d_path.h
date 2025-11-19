#pragma once

// clang-format off
#include "maps.h"
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
// clang-format on

/**
 * Reimplementation of the kernel d_path function.
 *
 * We should attempt to use bpf_d_path when possible, but you can't on
 * values that have been read using the bpf_probe_* helpers.
 */
__always_inline static long __d_path(const struct path* path, char* buf, int buflen) {
  if (buflen <= 0) {
    return -1;
  }

  struct helper_t* helper = get_helper();
  if (helper == NULL) {
    return -1;
  }

  struct task_struct* task = (struct task_struct*)bpf_get_current_task();
  int offset = (buflen - 1) & (PATH_MAX - 1);
  helper->buf[offset] = '\0';  // Ensure null termination

  struct path root;
  BPF_CORE_READ_INTO(&root, task, fs, root);
  struct mount* mnt = container_of(path->mnt, struct mount, mnt);
  struct dentry* dentry = BPF_CORE_READ(path, dentry);

  for (int i = 0; i < 16 && (dentry != root.dentry || &mnt->mnt != root.mnt); i++) {
    struct dentry* parent = BPF_CORE_READ(dentry, d_parent);
    struct dentry* mnt_root = BPF_CORE_READ(mnt, mnt.mnt_root);

    if (dentry == mnt_root) {
      struct mount* m = BPF_CORE_READ(mnt, mnt_parent);
      if (m != mnt) {
        dentry = BPF_CORE_READ(mnt, mnt_mountpoint);
        mnt = m;
        continue;
      }
      break;
    }

    if (dentry == parent) {
      return -1;
    }

    struct qstr d_name;
    BPF_CORE_READ_INTO(&d_name, dentry, d_name);
    int len = d_name.len;
    if (len <= 0 || len >= buflen) {
      return -1;
    }

    offset -= len;
    if (offset <= 0) {
      return -1;
    }

    if (bpf_probe_read_kernel(&helper->buf[offset], len, d_name.name) != 0) {
      return -1;
    }

    offset--;
    if (offset <= 0) {
      return -1;
    }
    helper->buf[offset] = '/';

    dentry = parent;
  }

  bpf_probe_read_str(buf, buflen, &helper->buf[offset]);
  return buflen - offset;
}

__always_inline static long d_path(struct path* path, char* buf, int buflen, bool use_bpf_helper) {
  if (use_bpf_helper) {
    return bpf_d_path(path, buf, buflen);
  }
  return __d_path(path, buf, buflen);
}
