#pragma once

// clang-format off
#include "vmlinux.h"
#include "types.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <sys/cdefs.h>
// clang-format on

__always_inline static int64_t process_fill(process_t* p, struct task_struct* task) {
  uint64_t uid_gid = bpf_get_current_uid_gid();
  p->uid = uid_gid & 0xFFFFFFFF;
  p->gid = (uid_gid >> 32) & 0xFFFFFFFF;
  p->login_uid = BPF_CORE_READ(task, loginuid.val);
  u_int64_t err = bpf_get_current_comm(p->comm, TASK_COMM_LEN);
  return err;
}
