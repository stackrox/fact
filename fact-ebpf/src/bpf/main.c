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

#define FMODE_WRITE ((fmode_t)(1 << 1))
#define FMODE_PWRITE ((fmode_t)(1 << 4))
#define FMODE_CREATED ((fmode_t)(1 << 20))

SEC("lsm/file_open")
int BPF_PROG(trace_file_open, struct file* file) {
  uint32_t key = 0;
  struct event_t* event = NULL;
  struct metrics_t* m = bpf_map_lookup_elem(&metrics, &key);
  if (m == NULL) {
    bpf_printk("Failed to get metrics entry, this should not happen");
    return 0;
  }

  m->file_open.total++;

  file_activity_type_t event_type = FILE_ACTIVITY_INIT;
  if ((file->f_mode & FMODE_CREATED) != 0) {
    event_type = FILE_ACTIVITY_CREATION;
  } else if ((file->f_mode & (FMODE_WRITE | FMODE_PWRITE)) != 0) {
    event_type = FILE_ACTIVITY_OPEN;
  } else {
    goto ignored;
  }

  struct path_cfg_helper_t* prefix_helper = bpf_map_lookup_elem(&path_prefix_helper, &key);
  if (prefix_helper == NULL) {
    bpf_printk("Failed to get prefix helper");
    goto error;
  }

  long len = bpf_d_path(&file->f_path, prefix_helper->path, PATH_MAX);
  if (len <= 0) {
    bpf_printk("Failed to read path");
    goto error;
  }

  if (len > LPM_SIZE_MAX) {
    len = LPM_SIZE_MAX;
  }
  // for LPM maps, the length is the total number of bits
  prefix_helper->bit_len = len * 8;

  if (!is_monitored(prefix_helper)) {
    goto ignored;
  }

  struct helper_t* helper = bpf_map_lookup_elem(&helper_map, &key);
  if (helper == NULL) {
    bpf_printk("Failed to get helper entry");
    return 0;
  }

  event = bpf_ringbuf_reserve(&rb, sizeof(struct event_t), 0);
  if (event == NULL) {
    m->file_open.ringbuffer_full++;
    bpf_printk("Failed to get event entry");
    return 0;
  }

  event->type = event_type;
  event->timestamp = bpf_ktime_get_boot_ns();
  bpf_probe_read_str(event->filename, PATH_MAX, prefix_helper->path);

  int64_t err = process_fill(&event->process);
  if (err) {
    bpf_printk("Failed to fill process information: %d", err);
    goto error;
  }

  const char* p = get_host_path(helper, file);
  if (p != NULL) {
    bpf_probe_read_str(event->host_file, PATH_MAX, p);
  }

  m->file_open.added++;
  bpf_ringbuf_submit(event, 0);

  return 0;

error:
  m->file_open.error++;
  if (event != NULL) {
    bpf_ringbuf_discard(event, 0);
  }
  return 0;

ignored:
  m->file_open.ignored++;
  return 0;
}
