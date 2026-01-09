#pragma once

// clang-format off
#include "vmlinux.h"

#include "d_path.h"
#include "maps.h"
#include "types.h"

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

__always_inline static void process_fill_lineage(process_t* p, struct helper_t* helper, bool use_bpf_d_path) {
  struct task_struct* task = (struct task_struct*)bpf_get_current_task_btf();
  p->lineage_len = 0;

  for (int i = 0; i < LINEAGE_MAX; i++) {
    struct task_struct* parent = task->real_parent;

    if (task == parent || parent->pid == 0) {
      return;
    }
    task = parent;

    p->lineage[i].uid = task->cred->uid.val;

    d_path(&task->mm->exe_file->f_path, p->lineage[i].exe_path, PATH_MAX, use_bpf_d_path);
    p->lineage_len++;
  }
}

__always_inline static unsigned long get_mount_ns() {
  struct task_struct* task = (struct task_struct*)bpf_get_current_task_btf();
  return task->nsproxy->mnt_ns->ns.inum;
}

__always_inline static int64_t process_fill(process_t* p, bool use_bpf_d_path) {
  struct task_struct* task = (struct task_struct*)bpf_get_current_task_btf();
  uint32_t key = 0;
  uint64_t uid_gid = bpf_get_current_uid_gid();
  p->uid = uid_gid & 0xFFFFFFFF;
  p->gid = (uid_gid >> 32) & 0xFFFFFFFF;
  p->login_uid = task->loginuid.val;
  p->pid = (bpf_get_current_pid_tgid() >> 32) & 0xFFFFFFFF;
  u_int64_t err = bpf_get_current_comm(p->comm, TASK_COMM_LEN);
  if (err != 0) {
    bpf_printk("Failed to fill task comm");
    return err;
  }

  unsigned long arg_start = task->mm->arg_start;
  unsigned long arg_end = task->mm->arg_end;
  p->args_len = (arg_end - arg_start) & 0xFFF;
  p->args[4095] = '\0';  // Ensure string termination at end of buffer
  err = bpf_probe_read_user(p->args, p->args_len, (const char*)arg_start);
  if (err != 0) {
    bpf_printk("Failed to fill task args");
    return err;
  }

  struct helper_t* helper = bpf_map_lookup_elem(&helper_map, &key);
  if (helper == NULL) {
    bpf_printk("Failed to get helper entry");
    return -1;
  }

  p->exe_path_len = d_path(&task->mm->exe_file->f_path, p->exe_path, PATH_MAX, use_bpf_d_path);

  const char* cg = get_memory_cgroup(helper);
  if (cg != NULL) {
    bpf_probe_read_str(p->memory_cgroup, PATH_MAX, cg);
  }

  p->in_root_mount_ns = get_mount_ns() == host_mount_ns;

  process_fill_lineage(p, helper, use_bpf_d_path);

  return 0;
}
