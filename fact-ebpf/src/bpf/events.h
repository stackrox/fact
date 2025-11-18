#pragma once

#include <bpf/bpf_helpers.h>

#include "maps.h"
#include "process.h"
#include "types.h"
#include "vmlinux.h"

__always_inline static void __submit_event(struct event_t* event, struct metrics_by_hook_t* m, file_activity_type_t event_type, const char filename[PATH_MAX], struct dentry* dentry) {
  event->type = event_type;
  event->timestamp = bpf_ktime_get_boot_ns();
  bpf_probe_read_str(event->filename, PATH_MAX, filename);

  struct helper_t* helper = get_helper();
  if (helper == NULL) {
    goto error;
  }

  const char* p = get_host_path(helper->buf, dentry);
  if (p != NULL) {
    bpf_probe_read_str(event->host_file, PATH_MAX, p);
  }

  int64_t err = process_fill(&event->process);
  if (err) {
    bpf_printk("Failed to fill process information: %d", err);
    goto error;
  }

  m->added++;
  bpf_ringbuf_submit(event, 0);
  return;

error:
  m->error++;
  bpf_ringbuf_discard(event, 0);
}

__always_inline static void submit_event(struct metrics_by_hook_t* m, file_activity_type_t event_type, const char filename[PATH_MAX], struct dentry* dentry) {
  struct event_t* event = bpf_ringbuf_reserve(&rb, sizeof(struct event_t), 0);
  if (event == NULL) {
    m->ringbuffer_full++;
    return;
  }

  __submit_event(event, m, event_type, filename, dentry);
}

__always_inline static void submit_mode_event(struct metrics_by_hook_t* m, const char filename[PATH_MAX], struct dentry* dentry, umode_t mode) {
  struct event_t* event = bpf_ringbuf_reserve(&rb, sizeof(struct event_t), 0);
  if (event == NULL) {
    m->ringbuffer_full++;
    return;
  }

  event->chmod.new = mode;
  event->chmod.old = BPF_CORE_READ(dentry, d_inode, i_mode);

  __submit_event(event, m, FILE_ACTIVITY_CHMOD, filename, dentry);
}
