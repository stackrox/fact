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
    uint64_t pref;
    uint64_t s_pref;
    memcpy(&pref, &prefix[offset], sizeof(pref));
    memcpy(&s_pref, &s[offset], sizeof(pref));

    if (s_pref != pref) {
      return false;
    }

    prefix_len -= 8;
  }

  for (int i = 0; i < prefix_len; i++) {
    if (s[i + offset] != prefix[i + offset]) {
      return false;
    }
  }

  return true;
}

__always_inline static void get_host_path(struct helper_t* helper, struct file* file) {
  struct dentry* d = BPF_CORE_READ(file, f_path.dentry);
  int total = 0;

  for (int i = 0; i < 16; i++) {
    total = i;
    const unsigned char* name = BPF_CORE_READ(d, d_name.name);
    if (name == NULL) {
      break;
    }
    helper->array[i] = name;

    struct dentry* parent = BPF_CORE_READ(d, d_parent);
    // if we reached the root
    if (parent == NULL || d == parent) {
      break;
    }
    d = parent;
  }

  unsigned int offset = 0;
  for (int i = total - 1; i >= 0 && offset < PATH_MAX; i--) {
    helper->buf[offset] = '/';
    offset++;

    if (offset >= PATH_MAX) {
      break;
    }

    int written = bpf_probe_read_str(&helper->buf[offset], PATH_MAX - offset, helper->array[i]);
    if (written < 0) {
      break;
    }
    if (helper->buf[offset] == '/') {
      helper->buf[offset] = '\0';
      offset--;
      continue;
    }

    // bytes written, excluding the null terminator
    offset += written - 1;
  }
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

__always_inline static bool is_external_mount(const struct file* file, const struct task_struct* task) {
  struct dentry* mnt = BPF_CORE_READ(file, f_path.mnt, mnt_root);
  struct dentry* task_root = BPF_CORE_READ(task, fs, root.dentry);

  return mnt != task_root;
}
