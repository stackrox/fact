#pragma once

// clang-format off
#include "types.h"
#include "maps.h"
#include "d_path.h"

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
// clang-format on

volatile const bool path_hooks_support_bpf_d_path;

__always_inline static char* path_safe_access(char* p, unsigned int offset) {
  return &p[PATH_LEN_CLAMP(offset)];
}

__always_inline static void path_write_char(char* p, unsigned int offset, char c) {
  *path_safe_access(p, offset) = c;
}

__always_inline static struct bound_path_t* _path_read(struct path* path, bound_path_buffer_t key, bool use_bpf_d_path) {
  struct bound_path_t* bound_path = get_bound_path(key);
  if (bound_path == NULL) {
    return NULL;
  }

  bound_path->len = d_path(path, bound_path->path, PATH_MAX, use_bpf_d_path);
  if (bound_path->len <= 0) {
    return NULL;
  }

  // Ensure length is within PATH_MAX for the verifier
  bound_path->len = PATH_LEN_CLAMP(bound_path->len);

  return bound_path;
}

__always_inline static struct bound_path_t* path_read_unchecked(struct path* path) {
  return _path_read(path, BOUND_PATH_MAIN, true);
}

__always_inline static struct bound_path_t* path_read(struct path* path) {
  return _path_read(path, BOUND_PATH_MAIN, path_hooks_support_bpf_d_path);
}

__always_inline static struct bound_path_t* path_read_alt(struct path* path) {
  return _path_read(path, BOUND_PATH_ALTERNATE, path_hooks_support_bpf_d_path);
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
  if (bpf_probe_read_kernel(path_offset, PATH_LEN_CLAMP(len), d_name.name)) {
    return PATH_APPEND_READ_ERROR;
  }

  path->len += len;
  path_write_char(path->path, path->len, '\0');

  return 0;
}

__always_inline static struct bound_path_t* _path_read_append_d_entry(struct path* dir, struct dentry* dentry, bound_path_buffer_t key) {
  struct bound_path_t* path = _path_read(dir, key, path_hooks_support_bpf_d_path);

  if (path == NULL) {
    bpf_printk("Failed to read path");
    return NULL;
  }
  path_write_char(path->path, path->len - 1, '/');

  switch (path_append_dentry(path, dentry)) {
    case PATH_APPEND_SUCCESS:
      break;
    case PATH_APPEND_INVALID_LENGTH:
      bpf_printk("Invalid path length: %u", path->len);
      return NULL;
    case PATH_APPEND_READ_ERROR:
      bpf_printk("Failed to read final path component");
      return NULL;
  }
  return path;
}

/**
 * Read the path and append the supplied dentry.
 *
 * A very common pattern in the kernel is to provide a struct path to a
 * directory and a dentry to an element in said directory, this helper
 * provides a short way of resolving the full path in one call.
 */
__always_inline static struct bound_path_t* path_read_append_d_entry(struct path* dir, struct dentry* dentry) {
  return _path_read_append_d_entry(dir, dentry, BOUND_PATH_MAIN);
}

/**
 * Read the path and append the supplied dentry.
 *
 * This works essentially the same as path_read_append_d_entry, but does
 * so in an alternate buffer. Useful for operations that take more than
 * one path, like path_rename.
 */
__always_inline static struct bound_path_t* path_read_alt_append_d_entry(struct path* dir, struct dentry* dentry) {
  return _path_read_append_d_entry(dir, dentry, BOUND_PATH_ALTERNATE);
}
