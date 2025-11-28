// clang-format off
#include "vmlinux.h"

#include "inode.h"
#include "file.h"
#include "types.h"
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
    goto error;
  }

  inode_key_t inode_key = inode_to_key(file->f_inode);
  const inode_value_t* inode = inode_get(&inode_key);

  struct dentry* parent = file->f_path.dentry->d_parent;
  inode_key_t parent_key = inode_to_key(parent->d_inode);
  inode_value_t* parent_inode = inode_get(&parent_key);

  switch (inode_is_monitored(inode, parent_inode)) {
    case NOT_MONITORED:
      // Check if the path is monitored by prefix
      if (!is_monitored(path)) {
        goto ignored;
      }
      bpf_printk("Not monitored: %s", path->path);
      break;

    case MONITORED:
      bpf_printk("Monitored: %s", path->path);
      break;
    case PARENT_MONITORED:
      if (event_type == FILE_ACTIVITY_CREATION) {
        inode = inode_new(file->f_inode);
        if (inode == NULL) {
          bpf_printk("Failed to insert inode object");
          goto error;
        }
      } else {
        goto ignored;
      }
      bpf_printk("Parent monitored: %s", path->path);
      break;
  }

  submit_event(&m->file_open, event_type, path->path, &inode_key, &parent_key, true);

  return 0;

ignored:
  m->file_open.ignored++;
  return 0;

error:
  m->file_open.error++;
  return 0;
}

SEC("lsm/path_unlink")
int BPF_PROG(trace_path_unlink, struct path* dir, struct dentry* dentry) {
  struct metrics_t* m = get_metrics();
  if (m == NULL) {
    return 0;
  }

  m->path_unlink.g.total++;

  struct bound_path_t* path = NULL;
  if (path_unlink_supports_bpf_d_path) {
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
  struct inode_key_t parent_key = inode_to_key(dir->dentry->d_inode);
  inode_value_t* parent_inode = inode_get(&parent_key);

  switch (inode_is_monitored(inode, parent_inode)) {
    case NOT_MONITORED:
      // Check if the path is monitored by prefix
      if (!is_monitored(path)) {
        m->path_unlink.g.ignored++;
        return 0;
      }
      break;

    case MONITORED:
      inode_remove(&inode_key);
      break;
    case PARENT_MONITORED:
      m->path_unlink.scan_miss++;
      return 0;
  }

  submit_event(&m->path_unlink.g,
               FILE_ACTIVITY_UNLINK,
               path->path,
               &inode_key,
               &parent_key,
               path_unlink_supports_bpf_d_path);
  return 0;

error:
  m->path_unlink.g.error++;
  return 0;
}
