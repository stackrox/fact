#pragma once

// clang-format off
#include "vmlinux.h"

#include "bound_path.h"
#include "inode.h"
#include "maps.h"
#include "process.h"
#include "types.h"

#include <bpf/bpf_helpers.h>
// clang-format on

struct submit_event_args_t {
  struct event_t* event;
  struct metrics_by_hook_t* metrics;
  const char* filename;
  inode_key_t inode;
  inode_key_t parent_inode;
  monitored_t monitored;
};

__always_inline static bool reserve_event(struct submit_event_args_t* args) {
  args->event = bpf_ringbuf_reserve(&rb, sizeof(struct event_t), 0);
  if (args->event == NULL) {
    args->metrics->ringbuffer_full++;
    return false;
  }
  return true;
}

__always_inline static void __submit_event(struct submit_event_args_t* args,
                                           bool use_bpf_d_path) {
  struct event_t* event = args->event;
  event->timestamp = bpf_ktime_get_boot_ns();
  event->monitored = args->monitored;
  inode_copy(&event->inode, &args->inode);
  inode_copy(&event->parent_inode, &args->parent_inode);
  if (args->filename != NULL) {
    bpf_probe_read_str(event->filename, PATH_MAX, args->filename);
  } else {
    event->filename[0] = '\0';
  }

  struct helper_t* helper = get_helper();
  if (helper == NULL) {
    goto error;
  }

  int64_t err = process_fill(&event->process, use_bpf_d_path);
  if (err) {
    bpf_printk("Failed to fill process information: %d", err);
    goto error;
  }

  args->metrics->added++;
  bpf_ringbuf_submit(event, 0);
  return;

error:
  args->metrics->error++;
  bpf_ringbuf_discard(event, 0);
}

__always_inline static void submit_open_event(struct submit_event_args_t* args,
                                              file_activity_type_t event_type) {
  if (!reserve_event(args)) {
    return;
  }
  args->event->type = event_type;

  __submit_event(args, true);
}

__always_inline static void submit_unlink_event(struct submit_event_args_t* args) {
  if (!reserve_event(args)) {
    return;
  }
  args->event->type = FILE_ACTIVITY_UNLINK;

  __submit_event(args, path_hooks_support_bpf_d_path);
}

__always_inline static void submit_mode_event(struct submit_event_args_t* args,
                                              umode_t mode,
                                              umode_t old_mode) {
  if (!reserve_event(args)) {
    return;
  }

  args->event->type = FILE_ACTIVITY_CHMOD;
  args->event->chmod.new = mode;
  args->event->chmod.old = old_mode;

  __submit_event(args, path_hooks_support_bpf_d_path);
}

__always_inline static void submit_ownership_event(struct submit_event_args_t* args,
                                                   unsigned long long uid,
                                                   unsigned long long gid,
                                                   unsigned long long old_uid,
                                                   unsigned long long old_gid) {
  if (!reserve_event(args)) {
    return;
  }

  args->event->type = FILE_ACTIVITY_CHOWN;
  args->event->chown.new.uid = uid;
  args->event->chown.new.gid = gid;
  args->event->chown.old.uid = old_uid;
  args->event->chown.old.gid = old_gid;

  __submit_event(args, path_hooks_support_bpf_d_path);
}

__always_inline static void submit_rename_event(struct submit_event_args_t* args,
                                                const char old_filename[PATH_MAX],
                                                inode_key_t* old_inode,
                                                monitored_t old_monitored) {
  if (!reserve_event(args)) {
    return;
  }

  args->event->type = FILE_ACTIVITY_RENAME;
  bpf_probe_read_str(args->event->rename.filename, PATH_MAX, old_filename);
  inode_copy(&args->event->rename.inode, old_inode);
  args->event->rename.monitored = old_monitored;

  __submit_event(args, path_hooks_support_bpf_d_path);
}

__always_inline static void submit_mkdir_event(struct submit_event_args_t* args) {
  if (!reserve_event(args)) {
    return;
  }
  args->event->type = DIR_ACTIVITY_CREATION;

  // d_instantiate doesn't support bpf_d_path, so we use false and rely on the stashed path from path_mkdir
  __submit_event(args, false);
}

__always_inline static void submit_rmdir_event(struct submit_event_args_t* args) {
  if (!reserve_event(args)) {
    return;
  }
  args->event->type = DIR_ACTIVITY_UNLINK;

  __submit_event(args, path_hooks_support_bpf_d_path);
}

__always_inline static void submit_xattr_event(struct submit_event_args_t* args,
                                               file_activity_type_t event_type,
                                               const char* xattr_name) {
  if (!reserve_event(args)) {
    return;
  }
  args->event->type = event_type;
  bpf_probe_read_str(args->event->xattr.name, XATTR_NAME_MAX_LEN, xattr_name);

  __submit_event(args, false);
}

__always_inline static void submit_acl_event(struct submit_event_args_t* args,
                                             const char* acl_name,
                                             struct posix_acl* kacl) {
  if (!reserve_event(args)) {
    return;
  }

  args->event->type = FILE_ACTIVITY_ACL_SET;

  // Determine ACL type from the xattr name.
  // "system.posix_acl_access" vs "system.posix_acl_default". name_buf
  // only needs to hold the longer of the two names, 25 bytes including
  // the null terminator, rounded up to the next power of two for
  // alignment.
  char name_buf[32] = {0};
  long name_len = bpf_probe_read_kernel_str(name_buf, sizeof(name_buf), acl_name);
  if (name_len == 25 && __builtin_memcmp(name_buf, "system.posix_acl_default", 24) == 0) {
    args->event->acl.acl_type = FACT_ACL_TYPE_DEFAULT;
  } else {
    args->event->acl.acl_type = FACT_ACL_TYPE_ACCESS;
  }

  if (kacl != NULL) {
    unsigned int count = 0;
    bpf_probe_read_kernel(&count, sizeof(count), &kacl->a_count);
    if (count > FACT_MAX_ACL_ENTRIES) {
      count = FACT_MAX_ACL_ENTRIES;
    }
    args->event->acl.count = count;

    for (unsigned int i = 0; i < FACT_MAX_ACL_ENTRIES && i < count; i++) {
      struct posix_acl_entry entry = {0};
      bpf_probe_read_kernel(&entry, sizeof(entry), &kacl->a_entries[i]);
      args->event->acl.entries[i].e_tag = (acl_tag_t)entry.e_tag;
      args->event->acl.entries[i].e_perm = entry.e_perm;
      // e_uid is only meaningful for USER/GROUP entries; the kernel
      // leaves it unset for USER_OBJ/GROUP_OBJ/MASK/OTHER, so we must
      // not read it for those tags.
      if (entry.e_tag == FACT_ACL_TAG_USER || entry.e_tag == FACT_ACL_TAG_GROUP) {
        args->event->acl.entries[i].e_id = entry.e_uid.val;
      } else {
        args->event->acl.entries[i].e_id = ACL_UNDEFINED_ID;
      }
    }
  } else {
    args->event->acl.count = 0;
  }

  // inode_set_acl does not support bpf_d_path (no struct path available)
  __submit_event(args, false);
}
