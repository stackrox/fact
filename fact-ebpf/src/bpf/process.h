#pragma once

#include "file.h"
#include "maps.h"
#include "types.h"

// clang-format off
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
// clang-format on

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
  p->cgroup_id = bpf_get_current_cgroup_id();
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

  d_path(&task->mm->exe_file->f_path, p->exe_path, PATH_MAX, use_bpf_d_path);

  p->in_root_mount_ns = get_mount_ns() == host_mount_ns;

  process_fill_lineage(p, helper, use_bpf_d_path);

  return 0;
}
