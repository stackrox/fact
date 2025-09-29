#pragma once

/**
 * This file is used to generate bindings to the Rust side and needs to
 * be kept as minimal as possible, avoid including vmlinux.h or any
 * other sources of bloat into this file.
 */

#define PATH_MAX 4096
#define TASK_COMM_LEN 16
#define LINEAGE_MAX 2

#define LPM_SIZE_MAX 256

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
  char in_root_mount_ns;
} process_t;

typedef enum file_activity_type_t {
  FILE_ACTIVITY_INIT = -1,
  FILE_ACTIVITY_OPEN = 0,
  FILE_ACTIVITY_CREATION,
} file_activity_type_t;

struct event_t {
  unsigned long timestamp;
  process_t process;
  char filename[PATH_MAX];
  char host_file[PATH_MAX];
  file_activity_type_t type;
};

/**
 * Used as the key for the path_prefix map.
 *
 * The memory layout is specific and must always have a 4 byte length
 * field first.
 *
 * See https://docs.ebpf.io/linux/map-type/BPF_MAP_TYPE_LPM_TRIE/
 * for a detailed description of how the LPM map works.
 */
struct path_prefix_t {
  unsigned int bit_len;
  const char path[LPM_SIZE_MAX];
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
