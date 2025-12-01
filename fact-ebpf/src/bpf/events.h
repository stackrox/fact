#pragma once

#include <bpf/bpf_helpers.h>

#include "maps.h"
#include "process.h"
#include "types.h"
#include "vmlinux.h"

__always_inline static void submit_event(struct metrics_by_hook_t* m, file_activity_type_t event_type, const char filename[PATH_MAX], const char* host_path, bool use_bpf_d_path) {
  struct event_t* event = bpf_ringbuf_reserve(&rb, sizeof(struct event_t), 0);
  if (event == NULL) {
    m->ringbuffer_full++;
    return;
  }

  event->type = event_type;
  event->timestamp = bpf_ktime_get_boot_ns();
  bpf_probe_read_str(event->filename, PATH_MAX, filename);

  if (host_path != NULL) {
    bpf_probe_read_str(event->host_file, PATH_MAX, host_path);
  } else {
    event->host_file[0] = '\0';
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
