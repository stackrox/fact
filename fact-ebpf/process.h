#pragma once

// clang-format off
#include "vmlinux.h"
#include "types.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
// clang-format on

__always_inline static int64_t process_fill(process_t* p, struct task_struct* task) {
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
  bpf_printk("len: %d", len);
  bpf_printk("arg_start: 0x%X", arg_start);
  bpf_printk("arg_end: 0x%X", arg_end);
  if (len > 4095) {
    len = 4095;
    p->args[4095] = '\0';  // Ensure empty string at end of buffer
  }
  err = bpf_probe_read_user(p->args, len, (const char*)arg_start);
  if (err != 0) {
    bpf_printk("Failed to fill task args");
    return err;
  }
  return 0;
}
