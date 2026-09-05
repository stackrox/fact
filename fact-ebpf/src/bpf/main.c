// clang-format off
#include "d_path.h"
#include "vmlinux.h"

#include "file.h"
#include "types.h"
#include "inode.h"
#include "maps.h"
#include "events.h"
#include "bound_path.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
// clang-format on

char _license[] SEC("license") = "Dual MIT/GPL";

#define FMODE_WRITE ((fmode_t)(1 << 1))
#define FMODE_PWRITE ((fmode_t)(1 << 4))
#define FMODE_CREATED ((fmode_t)(1 << 20))

#define STRINGIFY(a) STR(a)
#define STR(a) #a

#define __MAP0(m, ...)
#define __MAP1(m, t, a, ...) m(t, a)
#define __MAP2(m, t, a, ...) m(t, a), __MAP1(m, __VA_ARGS__)
#define __MAP3(m, t, a, ...) m(t, a), __MAP2(m, __VA_ARGS__)
#define __MAP4(m, t, a, ...) m(t, a), __MAP3(m, __VA_ARGS__)
#define __MAP5(m, t, a, ...) m(t, a), __MAP4(m, __VA_ARGS__)
#define __MAP6(m, t, a, ...) m(t, a), __MAP5(m, __VA_ARGS__)
#define __MAP(n, ...) __MAP##n(__VA_ARGS__)

#define __CAT(t, a) t a
#define __ARG(t, a) a

#define FACT_BPF_PROG(hook, n, args...)                             \
  static __always_inline int _handle_##hook(__MAP(n, __CAT, args)); \
  SEC("lsm/" STRINGIFY(hook))                                       \
  int BPF_PROG(trace_##hook, __MAP(n, __CAT, args)) {               \
    if (bpf_ksym_exists(bpf_preempt_disable)) {                     \
      bpf_preempt_disable();                                        \
    }                                                               \
    int res = _handle_##hook(__MAP(n, __ARG, args));                \
                                                                    \
    if (bpf_ksym_exists(bpf_preempt_enable)) {                      \
      bpf_preempt_enable();                                         \
    }                                                               \
    return res;                                                     \
  }                                                                 \
  static __always_inline int _handle_##hook(__MAP(n, __CAT, args))

#define FACT_BPF_PROG1(hook, args...) FACT_BPF_PROG(hook, 1, args)
#define FACT_BPF_PROG2(hook, args...) FACT_BPF_PROG(hook, 2, args)
#define FACT_BPF_PROG3(hook, args...) FACT_BPF_PROG(hook, 3, args)
#define FACT_BPF_PROG4(hook, args...) FACT_BPF_PROG(hook, 4, args)
#define FACT_BPF_PROG5(hook, args...) FACT_BPF_PROG(hook, 5, args)
#define FACT_BPF_PROG6(hook, args...) FACT_BPF_PROG(hook, 6, args)

FACT_BPF_PROG1(file_open, struct file*, file) {
  struct metrics_t* m = get_metrics();
  if (m == NULL) {
    return 0;
  }
  struct submit_event_args_t args = {.metrics = &m->file_open};

  args.metrics->total++;

  file_activity_type_t event_type = FILE_ACTIVITY_INIT;
  if ((file->f_mode & FMODE_CREATED) != 0) {
    event_type = FILE_ACTIVITY_CREATION;
  } else if ((file->f_mode & (FMODE_WRITE | FMODE_PWRITE)) != 0) {
    event_type = FILE_ACTIVITY_OPEN;
  } else {
    goto ignored;
  }

  // Overlayfs deduplication: overlayfs triggers file_open twice — once
  // on the overlay inode (with richer semantics like FMODE_CREATED) and
  // once on the underlying filesystem inode. We keep the overlayfs
  // event and skip the underlying duplicate.
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  if (inode_is_overlayfs(file->f_inode)) {
    char flag = 1;
    bpf_map_update_elem(&overlayfs_dedup, &pid_tgid, &flag, BPF_ANY);
  } else {
    char* flag = bpf_map_lookup_elem(&overlayfs_dedup, &pid_tgid);
    if (flag != NULL) {
      bpf_map_delete_elem(&overlayfs_dedup, &pid_tgid);
      goto ignored;
    }
  }

  struct bound_path_t* path = path_read_unchecked(&file->f_path, true);
  if (path == NULL) {
    bpf_printk("Failed to read path");
    m->file_open.error++;
    return 0;
  }
  args.filename = path->path;

  args.inode = inode_to_key(file->f_inode);

  struct dentry* parent_dentry = BPF_CORE_READ(file, f_path.dentry, d_parent);
  struct inode* parent_inode_ptr = parent_dentry ? BPF_CORE_READ(parent_dentry, d_inode) : NULL;
  args.parent_inode = inode_to_key(parent_inode_ptr);

  args.monitored = is_monitored(&args.inode, path, &args.parent_inode);
  if (args.monitored == NOT_MONITORED) {
    goto ignored;
  }

  if (args.monitored == MONITORED_BY_PARENT && event_type == FILE_ACTIVITY_CREATION) {
    inode_add(&args.inode);
  }

  submit_open_event(&args, event_type);
  return 0;

ignored:
  m->file_open.ignored++;
  return 0;
}

FACT_BPF_PROG2(path_unlink, struct path*, dir, struct dentry*, dentry) {
  struct metrics_t* m = get_metrics();
  if (m == NULL) {
    return 0;
  }
  struct submit_event_args_t args = {.metrics = &m->path_unlink};

  args.metrics->total++;

  struct bound_path_t* path = path_read_append_d_entry(dir, dentry);
  if (path == NULL) {
    bpf_printk("Failed to read path");
    m->path_unlink.error++;
    return 0;
  }
  args.filename = path->path;

  args.inode = inode_to_key(dentry->d_inode);
  args.monitored = is_monitored(&args.inode, path, NULL);

  if (args.monitored == NOT_MONITORED) {
    m->path_unlink.ignored++;
    return 0;
  }

  // We only support files with one link for now
  inode_remove(&args.inode);

  submit_unlink_event(&args);
  return 0;
}

FACT_BPF_PROG2(path_chmod, struct path*, path, umode_t, mode) {
  struct metrics_t* m = get_metrics();
  if (m == NULL) {
    return 0;
  }
  struct submit_event_args_t args = {.metrics = &m->path_chmod};

  args.metrics->total++;

  struct bound_path_t* bound_path = path_read(path);
  if (bound_path == NULL) {
    bpf_printk("Failed to read path");
    args.metrics->error++;
    return 0;
  }
  args.filename = bound_path->path;

  args.inode = inode_to_key(path->dentry->d_inode);
  args.monitored = is_monitored(&args.inode, bound_path, NULL);

  if (args.monitored == NOT_MONITORED) {
    args.metrics->ignored++;
    return 0;
  }

  umode_t old_mode = BPF_CORE_READ(path, dentry, d_inode, i_mode);
  submit_mode_event(&args, mode, old_mode);
  return 0;
}

/* path_chown takes _unsigned long long_ for uid and gid because kuid_t and kgid_t (structs)
   fit in registers and since they contain only one integer, their content is extended to the
   size of the BPF registers (64 bits) to simplify further arithmetic operations. */
FACT_BPF_PROG3(path_chown, struct path*, path, unsigned long long, uid, unsigned long long, gid) {
  struct metrics_t* m = get_metrics();
  if (m == NULL) {
    return 0;
  }
  struct submit_event_args_t args = {.metrics = &m->path_chown};

  args.metrics->total++;

  struct bound_path_t* bound_path = path_read(path);
  if (bound_path == NULL) {
    bpf_printk("Failed to read path");
    args.metrics->error++;
    return 0;
  }
  args.filename = bound_path->path;

  args.inode = inode_to_key(path->dentry->d_inode);
  args.monitored = is_monitored(&args.inode, bound_path, NULL);

  if (args.monitored == NOT_MONITORED) {
    args.metrics->ignored++;
    return 0;
  }

  struct dentry* d = BPF_CORE_READ(path, dentry);
  unsigned long long old_uid = BPF_CORE_READ(d, d_inode, i_uid.val);
  unsigned long long old_gid = BPF_CORE_READ(d, d_inode, i_gid.val);

  submit_ownership_event(&args, uid, gid, old_uid, old_gid);
  return 0;
}

FACT_BPF_PROG5(path_rename, struct path*, old_dir,
               struct dentry*, old_dentry, struct path*, new_dir,
               struct dentry*, new_dentry, unsigned int, flags) {
  struct metrics_t* m = get_metrics();
  if (m == NULL) {
    return 0;
  }
  struct submit_event_args_t args = {.metrics = &m->path_rename};

  args.metrics->total++;

  struct bound_path_t* new_path = path_read_append_d_entry(new_dir, new_dentry);
  if (new_path == NULL) {
    bpf_printk("Failed to read path");
    goto error;
  }
  args.filename = new_path->path;

  struct bound_path_t* old_path = path_read_alt_append_d_entry(old_dir, old_dentry);
  if (old_path == NULL) {
    bpf_printk("Failed to read path");
    goto error;
  }

  args.inode = inode_to_key(new_dentry->d_inode);
  args.parent_inode = inode_to_key(new_dir->dentry->d_inode);
  args.monitored = is_monitored(&args.inode, new_path, &args.parent_inode);

  inode_key_t old_inode = inode_to_key(old_dentry->d_inode);
  monitored_t old_monitored = is_monitored(&old_inode, old_path, NULL);

  // From this point on we need to handle inode tracking.
  //
  // The result will be a combination of whether we are already tracking
  // the old inode or not and whether the target path has an existing
  // object that is about to be overwritten and if said object is
  // tracked by inode or not.
  switch (args.monitored) {
    case NOT_MONITORED:
      if (old_monitored == NOT_MONITORED) {
        m->path_rename.ignored++;
        return 0;
      }

      if (old_monitored == MONITORED_BY_INODE) {
        // Old inode is monitored, new path is not.
        // If the old path is a directory userspace will remove any
        // subdirectories and files too.
        inode_remove(&old_inode);
      }
      break;

    case MONITORED_BY_PATH:
      if (old_monitored == MONITORED_BY_INODE) {
        // New path is not inode tracked, old path is.
        //
        // This implies the inode will be crossing a FS mountpoint,
        // which should never happen. When the inode crosses into a new
        // mount, a new inode is created altogether. Still, we can cover
        // our bases.
        inode_remove(&old_inode);
      }
      break;

    case MONITORED_BY_PARENT:
      if (old_monitored != MONITORED_BY_INODE) {
        // Old inode is not monitored, new parent is.
        if (inode_is_empty(&args.inode)) {
          // Landing on an empty path, we track the inode in case we
          // need to, userspace will double check in detail.
          inode_add(&old_inode);
        }
      } else if (!inode_is_empty(&args.inode)) {
        // Old inode is monitored and will land on a path that has a
        // monitored parent but the path itself is not monitored, we
        // stop tracking the inode
        inode_remove(&old_inode);
      }
      break;

    case MONITORED_BY_INODE:
      // If we landed here, the new path already has an inode that is
      // being tracked and is about to be overwritten, we need to remove
      // it from the map
      inode_remove(&args.inode);
      if (old_monitored != MONITORED_BY_INODE) {
        // Old inode is not monitored, but is landing in a monitored
        // path that uses inode tracking.
        inode_add(&old_inode);
      }
      break;
  }

  submit_rename_event(&args, old_path->path, &old_inode, old_monitored);
  return 0;

error:
  args.metrics->error++;
  return 0;
}

FACT_BPF_PROG3(path_mkdir, struct path*, dir, struct dentry*, dentry, umode_t, mode) {
  struct metrics_t* m = get_metrics();
  if (m == NULL) {
    return 0;
  }

  m->path_mkdir.total++;

  struct d_instantiate_ctx_t* mkdir_ctx = get_or_insert_d_instantiate_ctx();
  if (mkdir_ctx == NULL) {
    bpf_printk("Failed to get d_instantiate context entry");
    goto error;
  }

  if (path_read_into_append_d_entry(dir, dentry, &mkdir_ctx->path, path_hooks_support_bpf_d_path) == NULL) {
    bpf_printk("Failed to read path");
    goto error;
  }

  struct inode* parent_inode_ptr = BPF_CORE_READ(dir, dentry, d_inode);
  mkdir_ctx->parent_inode = inode_to_key(parent_inode_ptr);

  mkdir_ctx->monitored = is_monitored(NULL, &mkdir_ctx->path, &mkdir_ctx->parent_inode);
  if (mkdir_ctx->monitored != MONITORED_BY_PARENT) {
    delete_d_instantiate_ctx();
    m->path_mkdir.ignored++;
    return 0;
  }
  mkdir_ctx->event_type = DIR_ACTIVITY_CREATION;
  return 0;

error:
  delete_d_instantiate_ctx();
  m->path_mkdir.error++;
  return 0;
}

FACT_BPF_PROG2(d_instantiate, struct dentry*, dentry, struct inode*, inode) {
  struct metrics_t* m = get_metrics();
  if (m == NULL) {
    return 0;
  }
  struct submit_event_args_t args = {.metrics = &m->d_instantiate.base};

  args.metrics->total++;

  __u64 pid_tgid = bpf_get_current_pid_tgid();

  if (inode == NULL) {
    args.metrics->ignored++;
    goto cleanup;
  }

  struct d_instantiate_ctx_t* d_inst_ctx = get_d_instantiate_ctx();
  if (d_inst_ctx == NULL || d_inst_ctx->event_type == FILE_ACTIVITY_INIT) {
    args.metrics->ignored++;
    return 0;
  }
  args.filename = d_inst_ctx->path.path;
  args.parent_inode = d_inst_ctx->parent_inode;
  args.monitored = d_inst_ctx->monitored;

  args.inode = inode_to_key(inode);

  switch (d_inst_ctx->event_type) {
    case DIR_ACTIVITY_CREATION:
      if (inode_add(&args.inode) != 0) {
        args.metrics->error++;
      }

      m->d_instantiate.added_mkdir++;
      submit_mkdir_event(&args);
      break;
    case FILE_ACTIVITY_SYMLINK:
      args.monitored = is_monitored(&args.inode, &d_inst_ctx->path, &args.parent_inode);
      if (args.monitored == MONITORED_BY_PARENT) {
        if (inode_add(&args.inode) != 0) {
          args.metrics->error++;
        }
      }

      if (args.monitored != NOT_MONITORED) {
        m->d_instantiate.added_symlink++;
        submit_symlink_event(&args, d_inst_ctx->symlink_target);
      } else {
        args.metrics->ignored++;
      }
      break;
    default:
      bpf_printk("Unexpected event type: %d", d_inst_ctx->event_type);
      args.metrics->error++;
      break;
  }

cleanup:
  bpf_map_delete_elem(&d_instantiate_ctx, &pid_tgid);
  return 0;
}

__always_inline static int handle_xattr(struct metrics_by_hook_t* hook_metrics,
                                        struct dentry* dentry,
                                        const char* xattr_name,
                                        file_activity_type_t event_type) {
  struct submit_event_args_t args = {.metrics = hook_metrics};

  args.metrics->total++;

  args.inode = inode_to_key(dentry->d_inode);
  args.parent_inode = inode_to_key(BPF_CORE_READ(dentry, d_parent, d_inode));

  args.monitored = inode_is_monitored(inode_get(&args.inode), inode_get(&args.parent_inode));

  if (args.monitored == NOT_MONITORED) {
    args.metrics->ignored++;
    return 0;
  }

  submit_xattr_event(&args, event_type, xattr_name);
  return 0;
}

FACT_BPF_PROG6(inode_setxattr, struct mnt_idmap*, idmap, struct dentry*, dentry,
               const char*, name, const void*, value, size_t, size, int, flags) {
  struct metrics_t* m = get_metrics();
  if (m == NULL) {
    return 0;
  }
  return handle_xattr(&m->inode_setxattr, dentry, name, FILE_ACTIVITY_SETXATTR);
}

FACT_BPF_PROG3(inode_removexattr, struct mnt_idmap*, idmap, struct dentry*, dentry,
               const char*, name) {
  struct metrics_t* m = get_metrics();
  if (m == NULL) {
    return 0;
  }
  return handle_xattr(&m->inode_removexattr, dentry, name, FILE_ACTIVITY_REMOVEXATTR);
}

FACT_BPF_PROG4(inode_set_acl, struct mnt_idmap*, idmap, struct dentry*, dentry,
               const char*, acl_name, struct posix_acl*, kacl) {
  struct metrics_t* m = get_metrics();
  if (m == NULL) {
    return 0;
  }
  struct submit_event_args_t args = {.metrics = &m->inode_set_acl};

  args.metrics->total++;

  args.inode = inode_to_key(dentry->d_inode);
  args.parent_inode = inode_to_key(BPF_CORE_READ(dentry, d_parent, d_inode));

  args.monitored = inode_is_monitored(inode_get(&args.inode), inode_get(&args.parent_inode));

  if (args.monitored == NOT_MONITORED) {
    args.metrics->ignored++;
    return 0;
  }

  submit_acl_event(&args, acl_name, kacl);
  return 0;
}

FACT_BPF_PROG2(path_rmdir, struct path*, dir, struct dentry*, dentry) {
  struct metrics_t* m = get_metrics();
  if (m == NULL) {
    return 0;
  }
  struct submit_event_args_t args = {.metrics = &m->path_rmdir};

  args.metrics->total++;

  struct bound_path_t* path = path_read_append_d_entry(dir, dentry);
  if (path == NULL) {
    bpf_printk("Failed to read directory path");
    m->path_rmdir.error++;
    return 0;
  }
  args.filename = path->path;

  args.inode = inode_to_key(dentry->d_inode);

  if (inode_remove(&args.inode) < 0) {
    m->path_rmdir.ignored++;
    return 0;
  }

  submit_rmdir_event(&args);
  return 0;
}

FACT_BPF_PROG5(sb_mount, const char*, dev_name, struct path*, path, const char*, type, unsigned long, flags, void*, data) {
  struct metrics_t* m = get_metrics();
  if (m == NULL) {
    return 0;
  }
  struct submit_event_args_t args = {.metrics = &m->sb_mount};
  args.metrics->total++;

  struct bound_path_t* bound_path = path_read_unchecked(path, true);
  if (bound_path == NULL) {
    bpf_printk("Failed to read mount directory");
    args.metrics->error++;
    return 0;
  }
  args.filename = bound_path->path;

  args.inode = inode_to_key(path->dentry->d_inode);

  struct dentry* parent_dentry = BPF_CORE_READ(path, dentry, d_parent);
  struct inode* parent_inode_ptr = parent_dentry ? BPF_CORE_READ(parent_dentry, d_inode) : NULL;
  args.parent_inode = inode_to_key(parent_inode_ptr);

  args.monitored = is_monitored(&args.inode, bound_path, &args.parent_inode);
  if (args.monitored == NOT_MONITORED) {
    args.metrics->ignored++;
    return 0;
  }

  submit_mount_event(&args);
  return 0;
}

FACT_BPF_PROG2(sb_umount, struct vfsmount*, mnt, int, flags) {
  struct metrics_t* m = get_metrics();
  if (m == NULL) {
    return 0;
  }
  struct submit_event_args_t args = {.metrics = &m->sb_umount};
  args.metrics->total++;

  // TODO: Figure out a better way to read the path with bpf_path_d_path.
  struct bound_path_t* bound_path = get_bound_path(BOUND_PATH_MAIN);
  if (bound_path == NULL) {
    bpf_printk("Failed to get bound_path buffer");
    args.metrics->error++;
    return 0;
  }

  struct path p = {.dentry = BPF_CORE_READ(mnt, mnt_root), .mnt = mnt};
  if (__d_path(&p, bound_path->path, PATH_MAX) <= 0) {
    bpf_printk("Failed to read umount directory");
    args.metrics->error++;
    return 0;
  }
  args.filename = bound_path->path;

  args.inode = inode_to_key(mnt->mnt_root->d_inode);

  struct dentry* parent_dentry = BPF_CORE_READ(mnt, mnt_root, d_parent);
  struct inode* parent_inode_ptr = parent_dentry ? BPF_CORE_READ(parent_dentry, d_inode) : NULL;
  args.parent_inode = inode_to_key(parent_inode_ptr);

  args.monitored = is_monitored(&args.inode, bound_path, &args.parent_inode);
  if (args.monitored == NOT_MONITORED) {
    args.metrics->ignored++;
    return 0;
  }

  submit_umount_event(&args);
  return 0;
}

FACT_BPF_PROG2(move_mount, struct path*, from, struct path*, to) {
  struct metrics_t* m = get_metrics();
  if (m == NULL) {
    return 0;
  }
  struct submit_event_args_t args = {.metrics = &m->move_mount};

  args.metrics->total++;

  struct bound_path_t* to_path = path_read_unchecked(to, false);
  if (to_path == NULL) {
    bpf_printk("Failed to read to_path");
    goto error;
  }
  args.filename = to_path->path;

  struct bound_path_t* from_path = path_read_alt_unchecked(from, false);
  if (from_path == NULL) {
    bpf_printk("Failed to read from_path");
    goto error;
  }

  args.inode = inode_to_key(to->dentry->d_inode);
  args.parent_inode = inode_to_key(to->dentry->d_inode);
  args.monitored = is_monitored(&args.inode, to_path, &args.parent_inode);

  inode_key_t from_inode = inode_to_key(from->dentry->d_inode);
  monitored_t from_monitored = is_monitored(&from_inode, from_path, NULL);

  if (args.monitored != MONITORED_BY_INODE) {
    args.metrics->ignored++;
    return 0;
  }

  // Ensure the new mount is tracked.
  if (from_monitored != MONITORED_BY_INODE) {
    inode_add(&from_inode);
  }

  submit_move_mount_event(&args, from_path->path, &from_inode, from_monitored);
  return 0;

error:
  args.metrics->error++;
  return 0;
}

FACT_BPF_PROG3(path_symlink, struct path*, dir, struct dentry*, dentry, const char*, old_name) {
  struct metrics_t* m = get_metrics();
  if (m == NULL) {
    return 0;
  }
  m->path_symlink.total++;

  struct d_instantiate_ctx_t* symlink_ctx = get_or_insert_d_instantiate_ctx();
  if (symlink_ctx == NULL) {
    bpf_printk("Failed to get d_instantiate context entry");
    goto error;
  }

  if (path_read_into_append_d_entry(dir, dentry, &symlink_ctx->path, path_hooks_support_bpf_d_path) == NULL) {
    bpf_printk("Failed to read path");
    goto error;
  }

  symlink_ctx->parent_inode = inode_to_key(dir->dentry->d_inode);
  symlink_ctx->event_type = FILE_ACTIVITY_SYMLINK;

  if (bpf_probe_read_str(symlink_ctx->symlink_target, PATH_MAX, old_name) < 0) {
    bpf_printk("Failed to read old_name");
    goto error;
  }

  return 0;

error:
  delete_d_instantiate_ctx();
  m->path_symlink.error++;
  return 0;
}
