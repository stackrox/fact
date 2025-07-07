// clang-format off
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "Dual MIT/GPL";

#define FMODE_WRITE (0x2)
#define FMODE_PWRITE (0x10)

#ifndef memcmp
#define memcmp __builtin_memcmp
#endif

struct helper_t {
    char buf[4096];
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, struct helper_t);
  __uint(max_entries, 1);
} filename_map SEC(".maps");
// clang-format on

SEC("lsm/file_open")
int BPF_PROG(test_file_open, struct file* file) {
  uint32_t key = 0;
  if ((file->f_mode & (FMODE_WRITE | FMODE_PWRITE)) == 0) {
    return 0;
  }

  struct helper_t* filename = bpf_map_lookup_elem(&filename_map, &key);
  if (filename == NULL) {
    bpf_printk("Failed to get filename entry");
    return 0;
  }

  if (bpf_d_path(&file->f_path, filename->buf, 4096) < 0) {
    bpf_printk("Failed to read path");
    return 0;
  }

  if (memcmp("/root/test/etc/", filename->buf, 15) == 0) {
    bpf_printk("Got file open with write permissions on /root/test/etc");
  }

  return 0;
}
