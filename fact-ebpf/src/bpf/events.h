#pragma once

// clang-format off
#include "vmlinux.h"

#include "inode.h"
#include "maps.h"
#include "process.h"
#include "types.h"

#include <bpf/bpf_helpers.h>
// clang-format on

__always_inline static void __submit_event(struct event_t* event,
                                           struct metrics_by_hook_t* m,
                                           file_activity_type_t event_type,
                                           const char filename[PATH_MAX],
                                           inode_key_t* inode,
                                           bool use_bpf_d_path) {
  event->type = event_type;
  event->timestamp = bpf_ktime_get_boot_ns();
  inode_copy_or_reset(&event->inode, inode);
  bpf_probe_read_str(event->filename, PATH_MAX, filename);

  struct helper_t* helper = get_helper();
  if (helper == NULL) {
    goto error;
  }

  int64_t err = process_fill(&event->process, use_bpf_d_path);
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

__always_inline static void submit_event(struct metrics_by_hook_t* m,
                                         file_activity_type_t event_type,
                                         const char filename[PATH_MAX],
                                         inode_key_t* inode,
                                         bool use_bpf_d_path) {
  struct event_t* event = bpf_ringbuf_reserve(&rb, sizeof(struct event_t), 0);
  if (event == NULL) {
    m->ringbuffer_full++;
    return;
  }

  __submit_event(event, m, event_type, filename, inode, use_bpf_d_path);
}

__always_inline static void submit_mode_event(struct metrics_by_hook_t* m,
                                              const char filename[PATH_MAX],
                                              inode_key_t* inode,
                                              umode_t mode,
                                              umode_t old_mode,
                                              bool use_bpf_d_path) {
  struct event_t* event = bpf_ringbuf_reserve(&rb, sizeof(struct event_t), 0);
  if (event == NULL) {
    m->ringbuffer_full++;
    return;
  }

  event->chmod.new = mode;
  event->chmod.old = old_mode;

  __submit_event(event, m, FILE_ACTIVITY_CHMOD, filename, inode, use_bpf_d_path);
}

__always_inline static void submit_ownership_event(struct metrics_by_hook_t* m,
                                                   const char filename[PATH_MAX],
                                                   inode_key_t* inode,
                                                   unsigned long long uid,
                                                   unsigned long long gid,
                                                   unsigned long long old_uid,
                                                   unsigned long long old_gid,
                                                   bool use_bpf_d_path) {
  struct event_t* event = bpf_ringbuf_reserve(&rb, sizeof(struct event_t), 0);
  if (event == NULL) {
    m->ringbuffer_full++;
    return;
  }

  event->chown.new.uid = uid;
  event->chown.new.gid = gid;
  event->chown.old.uid = old_uid;
  event->chown.old.gid = old_gid;

  __submit_event(event, m, FILE_ACTIVITY_CHOWN, filename, inode, use_bpf_d_path);
}
