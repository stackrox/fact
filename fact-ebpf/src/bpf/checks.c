// clang-format off
#include "vmlinux.h"

#include "bound_path.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
// clang-format on

SEC("lsm/path_unlink")
int BPF_PROG(check_path_unlink_supports_bpf_d_path, struct path* dir, struct dentry* dentry) {
  struct bound_path_t* p = path_read(dir);
  bpf_printk("dir: %s", p->path);
  return 0;
}
