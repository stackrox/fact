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

typedef struct inode_key_t {
  unsigned int inode;
  unsigned int dev;
} inode_key_t;

// We can't use bool here because it is not a standard C type, we would
// need to include vmlinux.h but that would explode our Rust bindings.
// For the time being we just keep a char.
typedef char inode_value_t;

typedef enum file_activity_type_t {
  FILE_ACTIVITY_INIT = -1,
  FILE_ACTIVITY_OPEN = 0,
  FILE_ACTIVITY_CREATION,
  FILE_ACTIVITY_UNLINK,
} file_activity_type_t;

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
  struct metrics_by_hook_t path_unlink;
};
