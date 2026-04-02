// clang-format off
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

// File type constants from linux/stat.h
// https://github.com/torvalds/linux/blob/5619b098e2fbf3a23bf13d91897056a1fe238c6d/include/uapi/linux/stat.h
#define S_IFMT 00170000
#define S_IFDIR 0040000
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)

SEC("lsm/file_open")
int BPF_PROG(trace_file_open, struct file* file) {
  struct metrics_t* m = get_metrics();
  if (m == NULL) {
    return 0;
  }

  m->file_open.total++;

  file_activity_type_t event_type = FILE_ACTIVITY_INIT;
  if ((file->f_mode & FMODE_CREATED) != 0) {
    event_type = FILE_ACTIVITY_CREATION;
  } else if ((file->f_mode & (FMODE_WRITE | FMODE_PWRITE)) != 0) {
    event_type = FILE_ACTIVITY_OPEN;
  } else {
    goto ignored;
  }

  struct bound_path_t* path = path_read_unchecked(&file->f_path);
  if (path == NULL) {
    bpf_printk("Failed to read path");
    m->file_open.error++;
    return 0;
  }

  inode_key_t inode_key = inode_to_key(file->f_inode);
  inode_key_t* inode_to_submit = &inode_key;

  struct dentry* parent_dentry = BPF_CORE_READ(file, f_path.dentry, d_parent);
  struct inode* parent_inode_ptr = parent_dentry ? BPF_CORE_READ(parent_dentry, d_inode) : NULL;
  inode_key_t parent_key = inode_to_key(parent_inode_ptr);

  inode_monitored_t status = is_monitored(inode_key, path, &parent_key, &inode_to_submit);

  if (status == PARENT_MONITORED && event_type == FILE_ACTIVITY_CREATION) {
    inode_add(&inode_key);
  }

  if (status == NOT_MONITORED) {
    goto ignored;
  }

  submit_open_event(&m->file_open, event_type, path->path, inode_to_submit, &parent_key);

  return 0;

ignored:
  m->file_open.ignored++;
  return 0;
}

SEC("lsm/path_unlink")
int BPF_PROG(trace_path_unlink, struct path* dir, struct dentry* dentry) {
  struct metrics_t* m = get_metrics();
  if (m == NULL) {
    return 0;
  }

  m->path_unlink.total++;

  struct bound_path_t* path = path_read_append_d_entry(dir, dentry);
  if (path == NULL) {
    bpf_printk("Failed to read path");
    m->path_unlink.error++;
    return 0;
  }

  inode_key_t inode_key = inode_to_key(dentry->d_inode);
  inode_key_t* inode_to_submit = &inode_key;

  if (is_monitored(inode_key, path, NULL, &inode_to_submit) == NOT_MONITORED) {
    m->path_unlink.ignored++;
    return 0;
  }

  // We only support files with one link for now
  inode_remove(&inode_key);

  submit_unlink_event(&m->path_unlink,
                      path->path,
                      inode_to_submit,
                      NULL);
  return 0;
}

SEC("lsm/path_chmod")
int BPF_PROG(trace_path_chmod, struct path* path, umode_t mode) {
  struct metrics_t* m = get_metrics();
  if (m == NULL) {
    return 0;
  }

  m->path_chmod.total++;

  struct bound_path_t* bound_path = path_read(path);
  if (bound_path == NULL) {
    bpf_printk("Failed to read path");
    m->path_chmod.error++;
    return 0;
  }

  inode_key_t inode_key = inode_to_key(path->dentry->d_inode);
  inode_key_t* inode_to_submit = &inode_key;

  if (is_monitored(inode_key, bound_path, NULL, &inode_to_submit) == NOT_MONITORED) {
    m->path_chmod.ignored++;
    return 0;
  }

  umode_t old_mode = BPF_CORE_READ(path, dentry, d_inode, i_mode);
  submit_mode_event(&m->path_chmod,
                    bound_path->path,
                    inode_to_submit,
                    NULL,
                    mode,
                    old_mode);

  return 0;
}

/* path_chown takes _unsigned long long_ for uid and gid because kuid_t and kgid_t (structs)
   fit in registers and since they contain only one integer, their content is extended to the
   size of the BPF registers (64 bits) to simplify further arithmetic operations. */
SEC("lsm/path_chown")
int BPF_PROG(trace_path_chown, struct path* path, unsigned long long uid, unsigned long long gid) {
  struct metrics_t* m = get_metrics();
  if (m == NULL) {
    return 0;
  }

  m->path_chown.total++;

  struct bound_path_t* bound_path = path_read(path);
  if (bound_path == NULL) {
    bpf_printk("Failed to read path");
    m->path_chown.error++;
    return 0;
  }

  inode_key_t inode_key = inode_to_key(path->dentry->d_inode);
  inode_key_t* inode_to_submit = &inode_key;

  if (is_monitored(inode_key, bound_path, NULL, &inode_to_submit) == NOT_MONITORED) {
    m->path_chown.ignored++;
    return 0;
  }

  struct dentry* d = BPF_CORE_READ(path, dentry);
  unsigned long long old_uid = BPF_CORE_READ(d, d_inode, i_uid.val);
  unsigned long long old_gid = BPF_CORE_READ(d, d_inode, i_gid.val);

  submit_ownership_event(&m->path_chown,
                         bound_path->path,
                         inode_to_submit,
                         NULL,
                         uid,
                         gid,
                         old_uid,
                         old_gid);

  return 0;
}

SEC("lsm/path_rename")
int BPF_PROG(trace_path_rename, struct path* old_dir,
             struct dentry* old_dentry, struct path* new_dir,
             struct dentry* new_dentry, unsigned int flags) {
  struct metrics_t* m = get_metrics();
  if (m == NULL) {
    return 0;
  }

  m->path_rename.total++;

  struct bound_path_t* new_path = path_read_append_d_entry(new_dir, new_dentry);
  if (new_path == NULL) {
    bpf_printk("Failed to read path");
    goto error;
  }

  struct bound_path_t* old_path = path_read_alt_append_d_entry(old_dir, old_dentry);
  if (old_path == NULL) {
    bpf_printk("Failed to read path");
    goto error;
  }

  inode_key_t old_inode = inode_to_key(old_dentry->d_inode);
  inode_key_t new_inode = inode_to_key(new_dentry->d_inode);

  inode_key_t* old_inode_submit = &old_inode;
  inode_key_t* new_inode_submit = &new_inode;

  inode_monitored_t old_monitored = is_monitored(old_inode, old_path, NULL, &old_inode_submit);
  inode_monitored_t new_monitored = is_monitored(new_inode, new_path, NULL, &new_inode_submit);

  if (old_monitored == NOT_MONITORED && new_monitored == NOT_MONITORED) {
    m->path_rename.ignored++;
    return 0;
  }

  submit_rename_event(&m->path_rename,
                      new_path->path,
                      old_path->path,
                      old_inode_submit,
                      new_inode_submit,
                      NULL);
  return 0;

error:
  m->path_rename.error++;
  return 0;
}

SEC("lsm/path_mkdir")
int BPF_PROG(trace_path_mkdir, struct path* dir, struct dentry* dentry, umode_t mode) {
  struct metrics_t* m = get_metrics();
  if (m == NULL) {
    return 0;
  }

  m->path_mkdir.total++;

  struct bound_path_t* path = path_read_append_d_entry(dir, dentry);
  if (path == NULL) {
    bpf_printk("Failed to read path");
    m->path_mkdir.error++;
    return 0;
  }

  struct inode* parent_inode_ptr = BPF_CORE_READ(dir, dentry, d_inode);
  inode_key_t parent_inode = inode_to_key(parent_inode_ptr);

  if (should_track_mkdir(parent_inode, path) != PARENT_MONITORED) {
    m->path_mkdir.ignored++;
    return 0;
  }

  // Stash mkdir context for security_d_instantiate
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  struct mkdir_context_t* mkdir_ctx = get_mkdir_context();
  if (mkdir_ctx == NULL) {
    bpf_printk("Failed to get mkdir context buffer");
    m->path_mkdir.error++;
    return 0;
  }

  long path_copy_len = bpf_probe_read_str(mkdir_ctx->path, PATH_MAX, path->path);
  if (path_copy_len < 0) {
    bpf_printk("Failed to copy path string");
    m->path_mkdir.error++;
    return 0;
  }
  mkdir_ctx->parent_inode = parent_inode;

  if (bpf_map_update_elem(&mkdir_context, &pid_tgid, mkdir_ctx, BPF_ANY) != 0) {
    bpf_printk("Failed to stash mkdir context");
    m->path_mkdir.error++;
    return 0;
  }

  return 0;
}

SEC("lsm/d_instantiate")
int BPF_PROG(trace_d_instantiate, struct dentry* dentry, struct inode* inode) {
  struct metrics_t* m = get_metrics();
  if (m == NULL) {
    return 0;
  }

  m->d_instantiate.total++;

  if (inode == NULL) {
    m->d_instantiate.ignored++;
    return 0;
  }

  __u64 pid_tgid = bpf_get_current_pid_tgid();
  struct mkdir_context_t* mkdir_ctx = bpf_map_lookup_elem(&mkdir_context, &pid_tgid);
  if (mkdir_ctx == NULL) {
    m->d_instantiate.ignored++;
    return 0;
  }

  umode_t mode = BPF_CORE_READ(inode, i_mode);
  if (!S_ISDIR(mode)) {
    bpf_map_delete_elem(&mkdir_context, &pid_tgid);
    m->d_instantiate.ignored++;
    return 0;
  }

  inode_key_t inode_key = inode_to_key(inode);

  if (inode_add(&inode_key) == 0) {
    m->d_instantiate.added++;
  } else {
    m->d_instantiate.error++;
  }

  submit_mkdir_event(&m->d_instantiate,
                     mkdir_ctx->path,
                     &inode_key,
                     &mkdir_ctx->parent_inode);

  bpf_map_delete_elem(&mkdir_context, &pid_tgid);

  return 0;
}
