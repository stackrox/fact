#pragma once

// clang-format off
#include "vmlinux.h"

#include "inode.h"
#include "maps.h"
#include "process.h"
#include "types.h"

#include <bpf/bpf_helpers.h>
// clang-format on

__always_inline static void submit_event(struct metrics_by_hook_t* m,
                                         file_activity_type_t event_type,
                                         const char filename[PATH_MAX],
                                         inode_key_t* inode,
                                         inode_key_t* parent_inode,
                                         bool use_bpf_d_path) {
  struct event_t* event = bpf_ringbuf_reserve(&rb, sizeof(struct event_t), 0);
  if (event == NULL) {
    m->ringbuffer_full++;
    return;
  }

  event->type = event_type;
  event->timestamp = bpf_ktime_get_boot_ns();
  inode_copy_or_reset(&event->inode, inode);
  inode_copy_or_reset(&event->parent_inode, parent_inode);
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
