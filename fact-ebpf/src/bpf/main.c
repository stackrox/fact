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

  // For file creation events, check if the parent directory is being
  // monitored. If so, add the new file's inode to the tracked set.
  if (event_type == FILE_ACTIVITY_CREATION) {
    struct dentry* parent_dentry = BPF_CORE_READ(file, f_path.dentry, d_parent);
    if (parent_dentry) {
      struct inode* parent_inode = BPF_CORE_READ(parent_dentry, d_inode);
      inode_key_t parent_key = inode_to_key(parent_inode);

      if (inode_is_monitored(inode_get(&parent_key)) == MONITORED) {
        inode_add(&inode_key);
      }
    }
  }

  if (!is_monitored(inode_key, path, &inode_to_submit)) {
    goto ignored;
  }

  submit_open_event(&m->file_open, event_type, path->path, inode_to_submit);

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

  if (!is_monitored(inode_key, path, &inode_to_submit)) {
    m->path_unlink.ignored++;
    return 0;
  }

  submit_unlink_event(&m->path_unlink,
                      path->path,
                      inode_to_submit);
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

  if (!is_monitored(inode_key, bound_path, &inode_to_submit)) {
    m->path_chmod.ignored++;
    return 0;
  }

  umode_t old_mode = BPF_CORE_READ(path, dentry, d_inode, i_mode);
  submit_mode_event(&m->path_chmod,
                    bound_path->path,
                    inode_to_submit,
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

  if (!is_monitored(inode_key, bound_path, &inode_to_submit)) {
    m->path_chown.ignored++;
    return 0;
  }

  struct dentry* d = BPF_CORE_READ(path, dentry);
  unsigned long long old_uid = BPF_CORE_READ(d, d_inode, i_uid.val);
  unsigned long long old_gid = BPF_CORE_READ(d, d_inode, i_gid.val);

  submit_ownership_event(&m->path_chown,
                         bound_path->path,
                         inode_to_submit,
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

  bool old_monitored = is_monitored(old_inode, old_path, &old_inode_submit);
  bool new_monitored = is_monitored(new_inode, new_path, &new_inode_submit);

  if (!old_monitored && !new_monitored) {
    m->path_rename.ignored++;
    return 0;
  }

  submit_rename_event(&m->path_rename,
                      new_path->path,
                      old_path->path,
                      old_inode_submit,
                      new_inode_submit);
  return 0;

error:
  m->path_rename.error++;
  return 0;
}
