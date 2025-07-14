// clang-format off
#include "vmlinux.h"

#include "types.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "Dual MIT/GPL";

#define FMODE_WRITE (0x2)
#define FMODE_PWRITE (0x10)

#ifndef memcpy
#define memcpy __builtin_memcpy
#endif

struct helper_t {
  char buf[PATH_MAX * 2];
  const unsigned char* array[16];
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, struct helper_t);
  __uint(max_entries, 1);
} helper_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, struct path_cfg_t);
  __uint(max_entries, 64);
} paths_map SEC(".maps");

uint32_t paths_len;

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * sizeof(struct event_t));
} rb SEC(".maps");
// clang-format on

__always_inline bool has_prefix(const char* s, const char* prefix, uint64_t prefix_len) {
  if (prefix_len == 0) {
    return true;
  }

  if (prefix_len > PATH_MAX) {
    return false;
  }

  uint64_t offset = 0;
  while (prefix_len > 8) {
    uint64_t pref;
    uint64_t s_pref;
    memcpy(&pref, &prefix[offset], sizeof(pref));
    memcpy(&s_pref, &s[offset], sizeof(pref));

    if (s_pref != pref) {
      return false;
    }

    prefix_len -= 8;
  }

  for (int i = 0; i < prefix_len; i++) {
    if (s[i + offset] != prefix[i + offset]) {
      return false;
    }
  }

  return true;
}

__always_inline bool is_monitored(const char* s) {
  for (int key = 0; key < (paths_len & 0xF); key++) {
    struct path_cfg_t* path = bpf_map_lookup_elem(&paths_map, &key);
    if (path == NULL) {
      bpf_printk("Failed to get element %d in paths_map", key);
      break;
    }

    if (has_prefix(s, path->path, path->len)) {
      return true;
    }
  }
  return false;
}

__always_inline void get_path(struct helper_t* helper, struct dentry* d) {
  int total = 0;
  for (int i = 0; i < 16; i++) {
    total = i;
    const unsigned char* name = BPF_CORE_READ(d, d_name.name);
    if (name == NULL) {
      break;
    }
    helper->array[i] = name;

    struct dentry* parent = BPF_CORE_READ(d, d_parent);
    if (parent == NULL) {
      break;
    }
    d = parent;
  }

  unsigned int offset = 0;
  for (int i = total - 1; i >= 0 && offset < PATH_MAX; i--) {
    helper->buf[offset] = '/';
    offset++;

    if (offset >= PATH_MAX) {
      break;
    }

    int written = bpf_probe_read_str(&helper->buf[offset], PATH_MAX - offset, helper->array[i]);
    if (written < 0) {
      break;
    }
    if (helper->buf[offset] == '/') {
      helper->buf[offset] = '\0';
      offset--;
      continue;
    }

    // bytes written, excluding the null terminator
    offset += written - 1;
  }
}

SEC("lsm/file_open")
int BPF_PROG(test_file_open, struct file* file) {
  uint32_t key = 0;
  if ((file->f_mode & (FMODE_WRITE | FMODE_PWRITE)) == 0) {
    return 0;
  }

  struct helper_t* helper = bpf_map_lookup_elem(&helper_map, &key);
  if (helper == NULL) {
    bpf_printk("Failed to get helper entry");
    return 0;
  }

  struct event_t* event = bpf_ringbuf_reserve(&rb, sizeof(struct event_t), 0);
  if (event == NULL) {
    bpf_printk("Failed to get event entry");
    return 0;
  }

  if (bpf_d_path(&file->f_path, event->filename, PATH_MAX) < 0) {
    bpf_ringbuf_discard(event, 0);
    bpf_printk("Failed to read path");
    return 0;
  }

  if (is_monitored(event->filename)) {
    bpf_get_current_comm(event->comm, TASK_COMM_LEN);

    bpf_printk("comm: %s", event->comm);
    bpf_printk("filename: %s", event->filename);
    get_path(helper, file->f_path.dentry);
    bpf_printk("real_path: %s", helper->buf);
    bpf_probe_read_str(event->host_file, PATH_MAX, helper->buf);

    bpf_printk("Submitting event...");
    bpf_ringbuf_submit(event, 0);
  } else {
    bpf_ringbuf_discard(event, 0);
  }

  return 0;
}
