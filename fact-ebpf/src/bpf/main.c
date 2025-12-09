// clang-format off
#include "vmlinux.h"

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
    m->file_open.error++;
    return 0;
  }

  if (!is_monitored(path)) {
    goto ignored;
  }

  struct dentry* d = BPF_CORE_READ(file, f_path.dentry);
  submit_event(&m->file_open, event_type, path->path, d, true);

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

  if (!is_monitored(path)) {
    m->path_unlink.ignored++;
    return 0;
  }

  submit_event(&m->path_unlink, FILE_ACTIVITY_UNLINK, path->path, dentry, path_unlink_supports_bpf_d_path);
  return 0;

error:
  m->path_unlink.error++;
  return 0;
}

SEC("tp_btf/cgroup_attach_task")
int BPF_PROG(trace_cgroup_attach_task, struct cgroup* dst_cgrp, const char* path, struct task_struct* _task, bool _threadgroup) {
  struct metrics_t* m = get_metrics();
  if (m == NULL) {
    bpf_printk("Failed to get metrics entry");
    return 0;
  }

  m->cgroup_attach_task.total++;

  u64 id = dst_cgrp->kn->id;
  if (bpf_map_lookup_elem(&cgroup_map, &id) != NULL) {
    // Already have the entry
    m->cgroup_attach_task.ignored++;
    return 0;
  }

  struct helper_t* helper = get_helper();
  if (helper == NULL) {
    bpf_printk("Failed to get helper entry");
    m->cgroup_attach_task.error++;
    return 0;
  }

  bpf_core_read_str(helper->cgroup_entry.path, PATH_MAX, path);
  helper->cgroup_entry.parsed = false;
  int res = bpf_map_update_elem(&cgroup_map, &id, &helper->cgroup_entry, BPF_NOEXIST);
  if (res != 0) {
    bpf_printk("Failed to update path for %d", id);
    m->cgroup_attach_task.error++;
  }

  return 0;
}
