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

  struct bound_path_t* path = path_read(&file->f_path);
  if (path == NULL) {
    bpf_printk("Failed to read path");
    m->file_open.error++;
    return 0;
  }

  inode_key_t inode_key = inode_to_key(file->f_inode);
  const inode_value_t* inode = inode_get(&inode_key);
  switch (inode_is_monitored(inode)) {
    case NOT_MONITORED:
      if (!is_monitored(path)) {
        goto ignored;
      }
      break;
    case MONITORED:
      break;
  }

  submit_event(&m->file_open, event_type, path->path, &inode_key, true);

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

  struct bound_path_t* path = NULL;
  if (path_hooks_support_bpf_d_path) {
    path = path_read(dir);
  } else {
    path = path_read_no_d_path(dir);
  }

  if (path == NULL) {
    bpf_printk("Failed to read path");
    goto error;
  }
  path_write_char(path->path, path->len - 1, '/');

  switch (path_append_dentry(path, dentry)) {
    case PATH_APPEND_SUCCESS:
      break;
    case PATH_APPEND_INVALID_LENGTH:
      bpf_printk("Invalid path length: %u", path->len);
      goto error;
    case PATH_APPEND_READ_ERROR:
      bpf_printk("Failed to read final path component");
      goto error;
  }

  inode_key_t inode_key = inode_to_key(dentry->d_inode);
  const inode_value_t* inode = inode_get(&inode_key);

  switch (inode_is_monitored(inode)) {
    case NOT_MONITORED:
      if (!is_monitored(path)) {
        m->path_unlink.ignored++;
        return 0;
      }
      break;

    case MONITORED:
      inode_remove(&inode_key);
      break;
  }

  submit_event(&m->path_unlink,
               FILE_ACTIVITY_UNLINK,
               path->path,
               &inode_key,
               path_hooks_support_bpf_d_path);
  return 0;

error:
  m->path_unlink.error++;
  return 0;
}

SEC("lsm/path_chmod")
int BPF_PROG(trace_path_chmod, struct path* path, umode_t mode) {
  struct metrics_t* m = get_metrics();
  if (m == NULL) {
    return 0;
  }

  m->path_chmod.total++;

  struct bound_path_t* bound_path = NULL;
  if (path_hooks_support_bpf_d_path) {
    bound_path = path_read(path);
  } else {
    bound_path = path_read_no_d_path(path);
  }

  if (bound_path == NULL) {
    bpf_printk("Failed to read path");
    m->path_chmod.error++;
    return 0;
  }

  inode_key_t inode_key = inode_to_key(path->dentry->d_inode);
  const inode_value_t* inode = inode_get(&inode_key);

  switch (inode_is_monitored(inode)) {
    case NOT_MONITORED:
      if (!is_monitored(bound_path)) {
        m->path_chmod.ignored++;
        return 0;
      }
      break;

    case MONITORED:
      break;
  }

  umode_t old_mode = BPF_CORE_READ(path, dentry, d_inode, i_mode);
  submit_mode_event(&m->path_chmod,
                    bound_path->path,
                    &inode_key,
                    mode,
                    old_mode,
                    path_hooks_support_bpf_d_path);

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

  struct bound_path_t* bound_path = NULL;
  if (path_hooks_support_bpf_d_path) {
    bound_path = path_read(path);
  } else {
    bound_path = path_read_no_d_path(path);
  }

  if (bound_path == NULL) {
    bpf_printk("Failed to read path");
    m->path_chown.error++;
    return 0;
  }

  inode_key_t inode_key = inode_to_key(path->dentry->d_inode);
  const inode_value_t* inode = inode_get(&inode_key);

  switch (inode_is_monitored(inode)) {
    case NOT_MONITORED:
      if (!is_monitored(bound_path)) {
        m->path_chown.ignored++;
        return 0;
      }
      break;

    case MONITORED:
      break;
  }

  struct dentry* d = BPF_CORE_READ(path, dentry);
  kuid_t kuid = BPF_CORE_READ(d, d_inode, i_uid);
  kgid_t kgid = BPF_CORE_READ(d, d_inode, i_gid);
  unsigned long long old_uid = BPF_CORE_READ(&kuid, val);
  unsigned long long old_gid = BPF_CORE_READ(&kgid, val);

  submit_owner_event(&m->path_chown,
                     bound_path->path,
                     &inode_key,
                     uid,
                     gid,
                     old_uid,
                     old_gid,
                     path_hooks_support_bpf_d_path);

  return 0;
}
