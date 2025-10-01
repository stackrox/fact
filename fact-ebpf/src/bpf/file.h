#pragma once

// clang-format off
#include "vmlinux.h"

#include "builtins.h"
#include "types.h"
#include "maps.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
// clang-format on

#define PATH_MAX_MASK (PATH_MAX - 1)
#define path_len_clamp(len) ((len) & PATH_MAX_MASK)

__always_inline static char* path_safe_access(char* p, unsigned int offset) {
  return &p[path_len_clamp(offset)];
}

__always_inline static void path_write_char(char* p, unsigned int offset, char c) {
  *path_safe_access(p, offset) = c;
}

__always_inline static struct path_cfg_helper_t* path_read(struct path* path) {
  struct path_cfg_helper_t* prefix_helper = get_prefix_helper();

  prefix_helper->len = bpf_d_path(path, prefix_helper->path, PATH_MAX);
  if (prefix_helper->len <= 0) {
    return NULL;
  }

  // Ensure length is within PATH_MAX for the verifier
  prefix_helper->len = path_len_clamp(prefix_helper->len);

  return prefix_helper;
}

enum path_append_status_t {
  PATH_APPEND_SUCCESS = 0,
  PATH_APPEND_INVALID_LENGTH,
  PATH_APPEND_READ_ERROR,
};

__always_inline static enum path_append_status_t path_append_dentry(struct path_cfg_helper_t* path, struct dentry* dentry) {
  struct qstr d_name;
  BPF_CORE_READ_INTO(&d_name, dentry, d_name);
  int len = d_name.len;
  if (len + path->len > PATH_MAX) {
    path->len += len;
    return PATH_APPEND_INVALID_LENGTH;
  }

  char* path_offset = path_safe_access(path->path, path->len);
  if (bpf_probe_read_kernel(path_offset, path_len_clamp(len), d_name.name)) {
    return PATH_APPEND_READ_ERROR;
  }

  path->len += len;
  path_write_char(path->path, path->len, '\0');

  return 0;
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

__always_inline static bool is_monitored(struct path_cfg_helper_t* path) {
  if (!filter_by_prefix) {
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
