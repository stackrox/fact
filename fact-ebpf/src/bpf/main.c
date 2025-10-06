// clang-format off
#include "file.h"
#include "types.h"
#include "process.h"
#include "maps.h"
#include "events.h"
#include "bound_path.h"

#include "vmlinux.h"

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

  m->file_open.total++;

  file_activity_type_t event_type = FILE_ACTIVITY_INIT;
  if ((file->f_mode & FMODE_CREATED) != 0) {
    event_type = FILE_ACTIVITY_CREATION;
  } else if ((file->f_mode & (FMODE_WRITE | FMODE_PWRITE)) != 0) {
    event_type = FILE_ACTIVITY_OPEN;
  } else {
    goto ignored;
  }

  if (is_ignored(file->f_path.dentry->d_inode)) {
    goto ignored;
  }

  struct bound_path_t* path = path_read(&file->f_path);
  if (path == NULL) {
    bpf_printk("Failed to read path");
    m->file_open.error++;
    return 0;
  }

  if (!is_monitored(path)) {
    add_ignored(file->f_path.dentry->d_inode);
    goto ignored;
  }

  struct dentry* d = BPF_CORE_READ(file, f_path.dentry);
  submit_event(&m->file_open, event_type, path->path, d);

  return 0;

ignored:
  m->file_open.ignored++;
  return 0;
}

SEC("lsm/path_unlink")
int BPF_PROG(trace_path_unlink, struct path* dir, struct dentry* dentry) {
  struct metrics_t* m = get_metrics();

  m->path_unlink.total++;

  if (is_ignored(dentry->d_inode)) {
    goto ignored;
  }

  struct bound_path_t* path = path_read(dir);
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

  if (!is_monitored(path)) {
    goto ignored;
  }

  submit_event(&m->path_unlink, FILE_ACTIVITY_UNLINK, path->path, dentry);
  return 0;

error:
  m->path_unlink.error++;
  return 0;

ignored:
  m->path_unlink.ignored++;
  return 0;
}
