#pragma once

// clang-format off
#include "vmlinux.h"

#include "d_path.h"
#include "maps.h"
#include "types.h"
#include "raw_event.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
// clang-format on

__always_inline static const char* get_memory_cgroup(struct helper_t* helper) {
  if (!bpf_core_enum_value_exists(enum cgroup_subsys_id, memory_cgrp_id)) {
    return NULL;
  }

  struct task_struct* task = (struct task_struct*)bpf_get_current_task();

  // We're guessing which cgroup controllers are enabled for this task. The
  // assumption is that memory controller is present more often than
  // cpu & cpuacct.
  struct kernfs_node* kn = BPF_CORE_READ(task, cgroups, subsys[memory_cgrp_id], cgroup, kn);
  if (kn == NULL) {
    return NULL;
  }

  int i = 0;
  for (; i < 16; i++) {
    helper->array[i] = (const unsigned char*)BPF_CORE_READ(kn, name);
    if (bpf_core_field_exists(kn->__parent)) {
      kn = BPF_CORE_READ(kn, __parent);
    } else {
      struct kernfs_node___pre6_15 {
        struct kernfs_node* parent;
      };
      struct kernfs_node___pre6_15* kn_old = (void*)kn;
      kn = BPF_CORE_READ(kn_old, parent);
    }
    if (kn == NULL) {
      break;
    }
  }

  if (i == 16) {
    i--;
  }

  int offset = 0;
  for (; i >= 0 && offset < PATH_MAX; i--) {
    // Skip empty directories
    if (helper->array[i] == NULL) {
      continue;
    }

    helper->buf[offset & (PATH_MAX - 1)] = '/';
    if (++offset >= PATH_MAX) {
      return NULL;
    }

    int len = bpf_probe_read_kernel_str(&helper->buf[offset & (PATH_MAX - 1)], PATH_MAX, helper->array[i]);
    if (len < 0) {
      // We should have skipped all empty entries, any other error is a genuine
      // problem, stop processing.
      return NULL;
    }

    if (len == 1) {
      offset--;
      continue;
    }

    offset += len - 1;
  }

  return helper->buf;
}

__always_inline static long process_fill_lineage(struct raw_event_t* event, struct helper_t* helper, bool use_bpf_d_path) {
  struct task_struct* task = (struct task_struct*)bpf_get_current_task_btf();
  uint16_t lineage_len_pos = event->len;
  event->len += 2;

  uint16_t i = 0;
  for (; i < LINEAGE_MAX; i++) {
    struct task_struct* parent = task->real_parent;

    if (task == parent || parent->pid == 0) {
      break;
    }
    task = parent;

    raw_event_copy_uint(event, task->cred->uid.val);
    long err = raw_event_d_path(event, &task->mm->exe_file->f_path, use_bpf_d_path);
    if (err != 0) {
      bpf_printk("Failed to read lineage exe_path");
      return err;
    }
  }

  // go back and set the amount of lineage processes in the buffer
  uint16_t back = event->len;
  event->len = lineage_len_pos;

  raw_event_copy_uint(event, i);

  event->len = back;
  return 0;
}

__always_inline static unsigned long get_mount_ns() {
  struct task_struct* task = (struct task_struct*)bpf_get_current_task_btf();
  return task->nsproxy->mnt_ns->ns.inum;
}

/**
 * Fill in the information about the current process to the event
 * buffer.
 *
 * This method serializes all required process information for the event
 * as a binary blob into the provided event buffer. The serialized data
 * will look something like this:
 * |--|--|--|--|-------|--------------|-------------|------------|-|----|---|
 * |  |  |  |  |       |              |             |            | |    ^ grandparent lineage
 * |  |  |  |  |       |              |             |            | ^ parent lineage
 * |  |  |  |  |       |              |             |            ^ in_root_mount_ns
 * |  |  |  |  |       |              |             ^ cgroup
 * |  |  |  |  |       |              ^ executable path
 * |  |  |  |  |       ^ arguments
 * |  |  |  |  ^ comm
 * |  |  |  ^ pid
 * |  |  ^ loginuid
 * |  ^ gid
 * ^ uid
 */
__always_inline static int64_t process_fill(struct raw_event_t* event, bool use_bpf_d_path) {
  struct task_struct* task = (struct task_struct*)bpf_get_current_task_btf();
  uint32_t key = 0;
  uint64_t uid_gid = bpf_get_current_uid_gid();
  raw_event_copy_u32(event, uid_gid & 0xFFFFFFFF);
  raw_event_copy_u32(event, ((uid_gid >> 32) & 0xFFFFFFFF));
  raw_event_copy_uint(event, task->loginuid.val);
  raw_event_copy_u32(event, (bpf_get_current_pid_tgid() >> 32) & 0xFFFFFFFF);
  uint64_t err = raw_event_copy_comm(event);
  if (err != 0) {
    bpf_printk("Failed to fill task comm");
    return err;
  }

  unsigned long arg_start = task->mm->arg_start;
  unsigned long arg_end = task->mm->arg_end;
  uint16_t args_len = (arg_end - arg_start) & 0xFFF;
  err = raw_event_copy_buffer(event, (const void*)arg_start, args_len);
  if (err < 0) {
    bpf_printk("Failed to read process args");
    return -1;
  }

  err = raw_event_d_path(event, &task->mm->exe_file->f_path, use_bpf_d_path);
  if (err < 0) {
    bpf_printk("Failed to read exe_path");
    return -1;
  }

  struct helper_t* helper = bpf_map_lookup_elem(&helper_map, &key);
  if (helper == NULL) {
    bpf_printk("Failed to get helper entry");
    return -1;
  }

  const char* cg = get_memory_cgroup(helper);
  if (cg != NULL) {
    // Reserve space for the cgroup length
    event->len += 2;
    uint16_t cg_len = (uint16_t)bpf_probe_read_str(&event->buf[event->len], PATH_MAX, cg);

    // Move back and fix the length
    event->len -= 2;
    raw_event_copy_u16(event, cg_len - 1);

    // Forward past the cgroup
    event->len += ((cg_len - 1) & (PATH_MAX - 1));
  }

  raw_event_copy_u8(event, get_mount_ns() == host_mount_ns);

  err = process_fill_lineage(event, helper, use_bpf_d_path);
  if (err < 0) {
    return -1;
  }

  return 0;
}
