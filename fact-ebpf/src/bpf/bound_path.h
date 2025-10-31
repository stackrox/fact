#pragma once

// clang-format off
#include "types.h"
#include "maps.h"
#include "d_path.h"

#include "vmlinux.h"

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

__always_inline static struct bound_path_t* _path_read(struct path* path, bool use_bpf_d_path) {
  struct bound_path_t* bound_path = get_bound_path();
  if (bound_path == NULL) {
    return NULL;
  }

  bound_path->len = use_bpf_d_path ? bpf_d_path(path, bound_path->path, PATH_MAX) : d_path(path, bound_path->path, PATH_MAX);
  if (bound_path->len <= 0) {
    return NULL;
  }

  // Ensure length is within PATH_MAX for the verifier
  bound_path->len = path_len_clamp(bound_path->len);

  return bound_path;
}

__always_inline static struct bound_path_t* path_read(struct path* path) {
  return _path_read(path, true);
}

__always_inline static struct bound_path_t* path_read_no_d_path(struct path* path) {
  return _path_read(path, false);
}

enum path_append_status_t {
  PATH_APPEND_SUCCESS = 0,
  PATH_APPEND_INVALID_LENGTH,
  PATH_APPEND_READ_ERROR,
};

__always_inline static enum path_append_status_t path_append_dentry(struct bound_path_t* path, struct dentry* dentry) {
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
