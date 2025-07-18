#pragma once

#include "file.h"
#include "maps.h"
#include "types.h"

// clang-format off
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
// clang-format on

__always_inline static int64_t process_fill(process_t* p, struct task_struct* task) {
  uint32_t key = 0;
  uint64_t uid_gid = bpf_get_current_uid_gid();
  p->uid = uid_gid & 0xFFFFFFFF;
  p->gid = (uid_gid >> 32) & 0xFFFFFFFF;
  p->login_uid = BPF_CORE_READ(task, loginuid.val);
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

  return 0;
}
