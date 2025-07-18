// clang-format off
#include "file.h"
#include "types.h"
#include "process.h"
#include "maps.h"

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
// clang-format on

char _license[] SEC("license") = "Dual MIT/GPL";

#define FMODE_WRITE (0x2)
#define FMODE_PWRITE (0x10)

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
    bpf_printk("Failed to read path");
    goto end;
  }

  if (!is_monitored(event->filename)) {
    goto end;
  }

  struct task_struct* task = (struct task_struct*)bpf_get_current_task();
  if (task == NULL) {
    bpf_printk("Failed to get current task");
    goto end;
  }

  int64_t err = process_fill(&event->process, task);
  if (err) {
    bpf_printk("Failed to fill process information: %d", err);
    goto end;
  }

  event->is_external_mount = is_external_mount(file, task);

  if (event->is_external_mount) {
    get_host_path(helper, file);
    bpf_probe_read_str(event->host_file, PATH_MAX, helper->buf);
  } else {
    event->host_file[0] = '\0';
  }

  bpf_ringbuf_submit(event, 0);

  return 0;

end:
  bpf_ringbuf_discard(event, 0);
  return 0;
}
