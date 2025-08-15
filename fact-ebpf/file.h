#pragma once

// clang-format off
#include "vmlinux.h"

#include "builtins.h"
#include "types.h"
#include "maps.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
// clang-format on

__always_inline static bool has_prefix(const char* s, const char* prefix, uint64_t prefix_len) {
  if (prefix_len == 0) {
    return true;
  }

  if (prefix_len > PATH_MAX) {
    return false;
  }

  uint64_t offset = 0;
  while (prefix_len > 8) {
    uint64_t pref = *(uint64_t*)&prefix[offset];
    uint64_t s_pref = *(uint64_t*)&s[offset];

    if (s_pref != pref) {
      return false;
    }

    prefix_len -= 8;
    offset += 8;
  }

  for (int i = 0; i < prefix_len; i++) {
    if (s[i + offset] != prefix[i + offset]) {
      return false;
    }
  }

  return true;
}

/**
 * Reimplementation of the kernel d_path function.
 *
 * We should attempt to use bpf_d_path when possible, but you can't on
 * values that have been read using the bpf_probe_* helpers.
 */
__always_inline static char* d_path(const struct path* path, char* buf, int buflen) {
  if (buflen <= 0) {
    return NULL;
  }

  struct task_struct* task = (struct task_struct*)bpf_get_current_task();
  int offset = (buflen - 1) & (PATH_MAX - 1);
  buf[offset] = '\0';  // Ensure null termination

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
      return &buf[offset];
    }

    if (dentry == parent) {
      return NULL;
    }

    struct qstr d_name;
    BPF_CORE_READ_INTO(&d_name, dentry, d_name);
    int len = d_name.len;
    if (len <= 0 || len >= buflen) {
      return NULL;
    }

    offset -= len;
    if (offset <= 0) {
      return NULL;
    }

    if (bpf_probe_read_kernel(&buf[offset], len, d_name.name) != 0) {
      return NULL;
    }

    offset--;
    if (offset <= 0) {
      return NULL;
    }
    buf[offset] = '/';

    dentry = parent;
  }

  return &buf[offset];
}

__always_inline static char* get_host_path(struct helper_t* helper, struct file* file) {
  struct dentry* d = BPF_CORE_READ(file, f_path.dentry);
  int offset = PATH_MAX - 1;
  helper->buf[PATH_MAX - 1] = '\0';

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

    if (bpf_probe_read_kernel(&helper->buf[offset], len, d_name.name) != 0) {
      return NULL;
    }

    if (len == 1 && helper->buf[offset] == '/') {
      // Reached the root
      offset++;
      break;
    }

    offset--;
    helper->buf[offset] = '/';

    struct dentry* parent = BPF_CORE_READ(d, d_parent);
    // if we reached the root
    if (parent == NULL || d == parent) {
      break;
    }
    d = parent;
  }

  return &helper->buf[offset];
}

__always_inline static bool is_monitored(const char* s) {
  if (paths_len == 0) {
    return true;
  }

  for (int key = 0; key < (paths_len & 0xF); key++) {
    struct path_cfg_t* path = bpf_map_lookup_elem(&paths_map, &key);
    if (path == NULL) {
      bpf_printk("Failed to get element %d in paths_map", key);
      break;
    }

    if (has_prefix(s, path->path, path->len)) {
      return true;
    }
  }
  return false;
}

__always_inline static bool is_external_mount(const struct file* file) {
  struct task_struct* task = (struct task_struct*)bpf_get_current_task();
  struct dentry* mnt = BPF_CORE_READ(file, f_path.mnt, mnt_root);
  struct dentry* task_root = BPF_CORE_READ(task, fs, root.dentry);

  return mnt != task_root;
}
