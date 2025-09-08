#pragma once

/**
 * This file is used to generate bindings to the Rust side and needs to
 * be kept as minimal as possible, avoid including vmlinux.h or any
 * other sources of bloat into this file.
 */

#define PATH_MAX 4096
#define TASK_COMM_LEN 16
#define LINEAGE_MAX 2

typedef struct lineage_t {
  unsigned int uid;
  char exe_path[PATH_MAX];
} lineage_t;

typedef struct process_t {
  char comm[TASK_COMM_LEN];
  char args[4096];
  unsigned int args_len;
  char exe_path[PATH_MAX];
  char memory_cgroup[PATH_MAX];
  unsigned int uid;
  unsigned int gid;
  unsigned int login_uid;
  unsigned int pid;
  lineage_t lineage[LINEAGE_MAX];
  unsigned int lineage_len;
} process_t;

struct event_t {
  unsigned long timestamp;
  process_t process;
  unsigned long mnt_namespace;
  char filename[PATH_MAX];
  char host_file[PATH_MAX];
};

struct path_cfg_t {
  const char path[PATH_MAX];
  unsigned short len;
};

// Metrics types
struct metrics_by_hook_t {
  unsigned long long total;
  unsigned long long added;
  unsigned long long error;
  unsigned long long ignored;
  unsigned long long ringbuffer_full;
};

struct metrics_t {
  struct metrics_by_hook_t file_open;
};
