#ifndef _TYPES_H_
#define _TYPES_H_

/**
 * This file is used to generate bindings to the Rust side and needs to
 * be kept as minimal as possible, avoid including vmlinux.h or any
 * other sources of bloat into this file.
 */

#define TASK_COMM_LEN 16

struct event_t {
  char comm[TASK_COMM_LEN];
  char filename[4096];
  char host_file[4096];
};

#define PATH_MAX 4096

struct path_cfg_t {
  const char path[PATH_MAX];
  unsigned short len;
};

#endif  // _TYPES_H_
