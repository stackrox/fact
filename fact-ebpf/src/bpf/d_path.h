#pragma once

// clang-format off
#include "vmlinux.h"

#include "maps.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
// clang-format on

struct d_path_ctx {
  struct helper_t* helper;
  struct path root;
  struct mount* mnt;
  struct dentry* dentry;
  int offset;
  int buflen;
  bool success;
};

static long __d_path_inner(uint32_t index, void* _ctx) {
  struct d_path_ctx* ctx = (struct d_path_ctx*)_ctx;
  struct dentry* dentry = ctx->dentry;
  struct dentry* parent = BPF_CORE_READ(dentry, d_parent);
  struct mount* mnt = ctx->mnt;
  struct dentry* mnt_root = BPF_CORE_READ(mnt, mnt.mnt_root);

  if (dentry == mnt_root) {
    struct mount* m = BPF_CORE_READ(mnt, mnt_parent);
    if (m != mnt) {
      ctx->dentry = BPF_CORE_READ(mnt, mnt_mountpoint);
      ctx->mnt = m;
      return 0;
    }
    ctx->success = true;
    return 1;
  }

  if (dentry == parent) {
    return 1;
  }

  struct qstr d_name;
  BPF_CORE_READ_INTO(&d_name, dentry, d_name);
  int len = d_name.len & (PATH_MAX - 1);
  if (len <= 0 || len >= ctx->buflen) {
    return 1;
  }

  int offset = ctx->offset - len;
  if (offset <= 0) {
    return 1;
  }
  offset &= PATH_MAX - 1;

  if (bpf_probe_read_kernel(&ctx->helper->buf[offset], len, d_name.name) != 0) {
    return 1;
  }

  offset--;
  if (offset <= 0) {
    return 1;
  }
  ctx->helper->buf[offset] = '/';

  ctx->offset = offset;
  ctx->dentry = parent;
  return 0;
}

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

  int offset = (buflen - 1) & (PATH_MAX - 1);
  struct d_path_ctx ctx = {
      .buflen = buflen,
      .helper = get_helper(),
      .offset = offset,
  };

  if (ctx.helper == NULL) {
    return -1;
  }

  struct task_struct* task = (struct task_struct*)bpf_get_current_task();
  ctx.helper->buf[offset] = '\0';  // Ensure null termination

  BPF_CORE_READ_INTO(&ctx.root, task, fs, root);
  ctx.mnt = container_of(path->mnt, struct mount, mnt);
  BPF_CORE_READ_INTO(&ctx.dentry, path, dentry);

  long res = bpf_loop(PATH_MAX, __d_path_inner, &ctx, 0);
  if (res <= 0 || !ctx.success) {
    return -1;
  }

  bpf_probe_read_str(buf, buflen, &ctx.helper->buf[ctx.offset & (PATH_MAX - 1)]);
  return buflen - ctx.offset;
}

__always_inline static long d_path(struct path* path, char* buf, int buflen, bool use_bpf_helper) {
  if (use_bpf_helper) {
    return bpf_d_path(path, buf, buflen);
  }
  return __d_path(path, buf, buflen);
}
