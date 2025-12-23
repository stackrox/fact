#pragma once

// clang-format off
#include "vmlinux.h"

#include "maps.h"
#include "process.h"
#include "types.h"
#include "raw_event.h"

#include <bpf/bpf_helpers.h>
// clang-format on

/**
 * Format and submit an event to the ringbuffer.
 *
 * This method is responsible for using the provided values from
 * different BPF programs, serialize this data alongside the current
 * process information in a binary format and submit it as an event to
 * the ringbuffer.
 *
 * The high level format for an event can be described as follows:
 * |--|--------|---------------------------|---------------------------|
 * |  |        |                           |                          ^ event end
 * |  |        |                           ^ begin file data
 * |  |        ^ begin process data
 * |  ^ timestamp
 * ^ event type
 *
 * Event type: a 16 bit integer specifying the type of event this is.
 * Timestamp: the amount of nano seconds since boot time.
 * Process data: all the information collected from the current process.
 *   For more information on this field see the documentation for
 *   `process_fill`.
 * File data: information collected about the file being acted upon.
 *
 * The file data field can be expanded as follows:
 * |----|--------------|---|
 * |    |              ^ Event specific data
 * |    ^ file path
 * ^ inode information
 *
 * Inode information: Encoded as the inode and device numbers. Used for
 *   host path tracking.
 * File path: The path to the file being acted upon, retrieved from
 *   d_path.
 */
__always_inline static void submit_event(struct metrics_by_hook_t* m,
                                         file_activity_type_t event_type,
                                         struct bound_path_t* path,
                                         inode_key_t* inode,
                                         bool use_bpf_d_path) {
  unsigned int zero = 0;
  struct raw_event_t raw_event = {
      .buf = bpf_map_lookup_elem(&heap_map, &zero),
      .len = 0,
  };
  if (raw_event.buf == NULL) {
    m->error++;
    return;
  }

  raw_event_copy_u16(&raw_event, event_type);
  raw_event_copy_uint(&raw_event, bpf_ktime_get_boot_ns());

  int64_t err = process_fill(&raw_event, use_bpf_d_path);
  if (err) {
    bpf_printk("Failed to fill process information: %d", err);
    goto error;
  }

  // File data
  raw_event_copy_inode(&raw_event, inode);
  raw_event_copy_bound_path(&raw_event, path);

  if (bpf_ringbuf_output(&rb, raw_event.buf, raw_event.len, 0) != 0) {
    m->ringbuffer_full++;
    return;
  }
  m->added++;
  return;

error:
  m->error++;
}
