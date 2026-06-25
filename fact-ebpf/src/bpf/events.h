#pragma once

// clang-format off
#include "vmlinux.h"

#include "bound_path.h"
#include "inode.h"
#include "maps.h"
#include "process.h"
#include "types.h"
#include "raw_event.h"

#include <bpf/bpf_helpers.h>
// clang-format on

struct submit_event_args_t {
  struct metrics_by_hook_t* metrics;
  struct bound_path_t* filename;
  inode_key_t inode;
  inode_key_t parent_inode;
  monitored_t monitored;
};

__always_inline static long fill_base_event(struct submit_event_args_t* args,
                                            struct raw_event_t* event,
                                            file_activity_type_t type,
                                            bool use_bpf_d_path) {
  raw_event_copy_u16(event, type);
  raw_event_copy_u64(event, bpf_ktime_get_boot_ns());

  int64_t err = process_fill(event, use_bpf_d_path);
  if (err) {
    bpf_printk("Failed to fill process information: %d", err);
    return -1;
  }

  // File data
  raw_event_copy_u8(event, args->monitored);
  raw_event_copy_inode(event, &args->inode);
  raw_event_copy_inode(event, &args->parent_inode);
  raw_event_copy_bound_path(event, args->filename);

  return 0;
}

__always_inline static void __submit_event(struct submit_event_args_t* args, struct raw_event_t* event) {
  if (bpf_ringbuf_output(&rb, event->buf, event->len, 0) != 0) {
    args->metrics->ringbuffer_full++;
    return;
  }
  args->metrics->added++;
}

__always_inline static void submit_open_event(struct submit_event_args_t* args,
                                              file_activity_type_t type) {
  struct raw_event_t event = INIT_RAW_EVENT();
  if (event.buf == NULL) {
    goto error;
  }

  if (fill_base_event(args, &event, type, true) != 0) {
    goto error;
  }

  __submit_event(args, &event);
  return;

error:
  args->metrics->error++;
}

__always_inline static void submit_unlink_event(struct submit_event_args_t* args) {
  struct raw_event_t event = INIT_RAW_EVENT();
  if (event.buf == NULL) {
    goto error;
  }

  if (fill_base_event(args, &event, FILE_ACTIVITY_UNLINK, path_hooks_support_bpf_d_path) != 0) {
    goto error;
  }

  __submit_event(args, &event);
  return;

error:
  args->metrics->error++;
}

__always_inline static void submit_mode_event(struct submit_event_args_t* args,
                                              umode_t mode,
                                              umode_t old_mode) {
  struct raw_event_t event = INIT_RAW_EVENT();
  if (event.buf == NULL) {
    goto error;
  }

  if (fill_base_event(args, &event, FILE_ACTIVITY_CHMOD, path_hooks_support_bpf_d_path) != 0) {
    goto error;
  }

  raw_event_copy_u16(&event, mode);
  raw_event_copy_u16(&event, old_mode);

  __submit_event(args, &event);
  return;

error:
  args->metrics->error++;
}

__always_inline static void submit_ownership_event(struct submit_event_args_t* args,
                                                   unsigned long long uid,
                                                   unsigned long long gid,
                                                   unsigned long long old_uid,
                                                   unsigned long long old_gid) {
  struct raw_event_t event = INIT_RAW_EVENT();
  if (event.buf == NULL) {
    goto error;
  }

  if (fill_base_event(args, &event, FILE_ACTIVITY_CHOWN, path_hooks_support_bpf_d_path) != 0) {
    goto error;
  }

  raw_event_copy_u32(&event, uid);
  raw_event_copy_u32(&event, gid);
  raw_event_copy_u32(&event, old_uid);
  raw_event_copy_u32(&event, old_gid);

  __submit_event(args, &event);
  return;

error:
  args->metrics->error++;
}

__always_inline static void submit_rename_event(struct submit_event_args_t* args,
                                                const struct bound_path_t* const filename,
                                                inode_key_t* old_inode,
                                                monitored_t old_monitored) {
  struct raw_event_t event = INIT_RAW_EVENT();
  if (event.buf == NULL) {
    goto error;
  }

  if (fill_base_event(args, &event, FILE_ACTIVITY_RENAME, path_hooks_support_bpf_d_path) != 0) {
    goto error;
  }

  raw_event_copy_u8(&event, old_monitored);
  raw_event_copy_inode(&event, old_inode);
  raw_event_copy_bound_path(&event, filename);

  __submit_event(args, &event);
  return;

error:
  args->metrics->error++;
}

__always_inline static void submit_mkdir_event(struct submit_event_args_t* args) {
  struct raw_event_t event = INIT_RAW_EVENT();
  if (event.buf == NULL) {
    goto error;
  }

  if (fill_base_event(args, &event, DIR_ACTIVITY_CREATION, false) != 0) {
    goto error;
  }

  __submit_event(args, &event);
  return;

error:
  args->metrics->error++;
}

__always_inline static void submit_rmdir_event(struct submit_event_args_t* args) {
  struct raw_event_t event = INIT_RAW_EVENT();
  if (event.buf == NULL) {
    goto error;
  }

  if (fill_base_event(args, &event, DIR_ACTIVITY_UNLINK, path_hooks_support_bpf_d_path) != 0) {
    goto error;
  }

  __submit_event(args, &event);
  return;

error:
  args->metrics->error++;
}
