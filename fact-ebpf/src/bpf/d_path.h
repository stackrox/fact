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

static long __d_path_inner(uint32_t index, void* _ctx) {
  struct d_path_ctx* ctx = (struct d_path_ctx*)_ctx;
  struct dentry* dentry = ctx->dentry;
  struct dentry* parent = BPF_CORE_READ(dentry, d_parent);
  struct mount* mnt = ctx->mnt;
  struct dentry* mnt_root = BPF_CORE_READ(mnt, mnt.mnt_root);

  if (dentry == ctx->root->dentry && &mnt->mnt == ctx->root->mnt) {
    // Found the root of the process, we are done
    ctx->success = true;
    return 1;
  }

  if (dentry == mnt_root) {
    struct mount* m = BPF_CORE_READ(mnt, mnt_parent);
    if (m != mnt) {
      // Current dentry is a mount root different to the previous one we
      // had (to prevent looping), switch over to that mount position
      // and keep walking up the path.
      ctx->dentry = BPF_CORE_READ(mnt, mnt_mountpoint);
      ctx->mnt = m;
      return 0;
    }

    // Ended up in a global root, the path might need re-processing or
    // the root is not attached yet, we are not getting a better path,
    // so we assume we are correct and stop iterating.
    ctx->success = true;
    return 1;
  }

  if (dentry == parent) {
    // We escaped the mounts and ended up at (most likely) the root of
    // the device, the path we formed will be wrong.
    //
    // This may happen in race conditions where some dentries go away
    // while we are iterating.
    return 1;
  }

  struct qstr d_name;
  BPF_CORE_READ_INTO(&d_name, dentry, d_name);
  int len = PATH_LEN_CLAMP(d_name.len);
  if (len <= 0 || len >= ctx->buflen) {
    return 1;
  }

  int offset = ctx->offset - len;
  if (offset <= 0) {
    return 1;
  }
  offset = PATH_LEN_CLAMP(offset);

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

  int offset = PATH_LEN_CLAMP(buflen - 1);
  struct d_path_ctx ctx = {
      .buflen = buflen,
      .helper = get_helper(),
      .offset = offset,
  };

  if (ctx.helper == NULL) {
    return -1;
  }

  struct task_struct* task = (struct task_struct*)bpf_get_current_task_btf();
  ctx.helper->buf[offset] = '\0';  // Ensure null termination

  ctx.root = &task->fs->root;
  ctx.mnt = container_of(path->mnt, struct mount, mnt);
  BPF_CORE_READ_INTO(&ctx.dentry, path, dentry);

  long res = bpf_loop(PATH_MAX, __d_path_inner, &ctx, 0);
  if (res <= 0 || !ctx.success) {
    return -1;
  }

  bpf_probe_read_str(buf, buflen, &ctx.helper->buf[PATH_LEN_CLAMP(ctx.offset)]);
  return buflen - ctx.offset;
}

__always_inline static long d_path(struct path* path, char* buf, int buflen, bool use_bpf_helper) {
  if (use_bpf_helper) {
    return bpf_d_path(path, buf, buflen);
  }
  return __d_path(path, buf, buflen);
}
