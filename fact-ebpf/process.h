#pragma once

#include "file.h"
#include "maps.h"
#include "types.h"

// clang-format off
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
// clang-format on

__always_inline static const char* get_cpu_cgroup(struct helper_t* helper) {
  if (!bpf_core_enum_value_exists(enum cgroup_subsys_id, cpu_cgrp_id)) {
    return NULL;
  }

  struct task_struct* task = (struct task_struct*)bpf_get_current_task();
  struct kernfs_node* kn = BPF_CORE_READ(task, cgroups, subsys[cpu_cgrp_id], cgroup, kn);
  if (kn == NULL) {
    return NULL;
  }

  int i = 0;
  for (; i < 16; i++) {
    helper->array[i] = (const unsigned char*)BPF_CORE_READ(kn, name);
    if (bpf_core_field_exists(kn->__parent)) {
      kn = BPF_CORE_READ(kn, __parent);
    } else {
      struct {
        struct kernfs_node* parent;
      }* kn_old = (void*)kn;
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
    helper->buf[offset & (PATH_MAX - 1)] = '/';
    if (++offset >= PATH_MAX) {
      return NULL;
    }

    int len = bpf_probe_read_kernel_str(&helper->buf[offset & (PATH_MAX - 1)], PATH_MAX, helper->array[i]);
    if (len < 0) {
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

__always_inline static void process_fill_lineage(process_t* p, struct helper_t* helper) {
  struct task_struct* task = (struct task_struct*)bpf_get_current_task();
  struct path path;
  p->lineage_len = 0;

  for (int i = 0; i < LINEAGE_MAX; i++) {
    struct task_struct* parent = BPF_CORE_READ(task, real_parent);
    if (task == parent || BPF_CORE_READ(parent, pid) == 0) {
      return;
    }
    task = parent;

    p->lineage[i].uid = BPF_CORE_READ(task, cred, uid.val);

    BPF_CORE_READ_INTO(&path, task, mm, exe_file, f_path);
    char* exe_path = d_path(&path, helper->buf, PATH_MAX);
    bpf_probe_read_kernel_str(p->lineage[i].exe_path, PATH_MAX, exe_path);
    p->lineage_len++;
  }
}

__always_inline static int64_t process_fill(process_t* p) {
  struct task_struct* task = (struct task_struct*)bpf_get_current_task();
  uint32_t key = 0;
  uint64_t uid_gid = bpf_get_current_uid_gid();
  p->uid = uid_gid & 0xFFFFFFFF;
  p->gid = (uid_gid >> 32) & 0xFFFFFFFF;
  p->login_uid = BPF_CORE_READ(task, loginuid.val);
  p->pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
  u_int64_t err = bpf_get_current_comm(p->comm, TASK_COMM_LEN);
  if (err != 0) {
    bpf_printk("Failed to fill task comm");
    return err;
  }

  unsigned long arg_start = BPF_CORE_READ(task, mm, arg_start);
  unsigned long arg_end = BPF_CORE_READ(task, mm, arg_end);
  unsigned int len = arg_end - arg_start;
  if (len > 4095) {
    len = 4095;
    p->args[4095] = '\0';  // Ensure empty string at end of buffer
  }
  err = bpf_probe_read_user(p->args, len, (const char*)arg_start);
  if (err != 0) {
    bpf_printk("Failed to fill task args");
    return err;
  }

  struct helper_t* helper = bpf_map_lookup_elem(&helper_map, &key);
  if (helper == NULL) {
    bpf_printk("Failed to get helper entry");
    return -1;
  }

  struct path path;
  BPF_CORE_READ_INTO(&path, task, mm, exe_file, f_path);

  const char* exe_path = d_path(&path, helper->buf, PATH_MAX);
  if (exe_path == NULL) {
    bpf_printk("failed to get exe_path");
    return -1;
  }
  bpf_probe_read_str(p->exe_path, PATH_MAX, exe_path);

  const char* cg = get_cpu_cgroup(helper);
  if (cg != NULL) {
    bpf_probe_read_str(p->cpu_cgroup, PATH_MAX, cg);
  }

  process_fill_lineage(p, helper);

  return 0;
}
