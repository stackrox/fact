#pragma once

/**
 * This file is used to generate bindings to the Rust side and needs to
 * be kept as minimal as possible, avoid including vmlinux.h or any
 * other sources of bloat into this file.
 */

/**
 * Kernel constant, taken from:
 * https://github.com/torvalds/linux/blob/f0b9d8eb98dfee8d00419aa07543bdc2c1a44fb1/include/uapi/linux/limits.h#L13
 */
#define PATH_MAX 4096
#define TASK_COMM_LEN 16

#define LINEAGE_MAX 2

// Matches Linux kernel XATTR_NAME_MAX (255) + null terminator.
// https://github.com/torvalds/linux/blob/66affa37cfac0aec061cc4bcf4a065b0c52f7e19/include/uapi/linux/limits.h#L15
#define XATTR_NAME_MAX_LEN 256

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

typedef struct inode_key_t {
  unsigned long inode;
  unsigned long dev;
} inode_key_t;

typedef enum monitored_t {
  NOT_MONITORED = 0,
  MONITORED_BY_INODE,
  MONITORED_BY_PATH,
  MONITORED_BY_PARENT,
} monitored_t;

// We can't use bool here because it is not a standard C type, we would
// need to include vmlinux.h but that would explode our Rust bindings.
// For the time being we just keep a char.
typedef char inode_value_t;

// Generic xattr values are capped at XATTR_SIZE_MAX (64KiB), which bounds
// a POSIX ACL xattr (4 byte header + 8 bytes per entry) to ~8191 entries
// in theory:
// https://github.com/torvalds/linux/blob/d2c9a99135da931377240942d44f3dea104cedb8/include/uapi/linux/limits.h#L16
// In practice, individual filesystems impose much lower limits tied to
// their own xattr/block storage (e.g. ext4 caps out in the low hundreds
// for a typical 4K xattr block). 32 comfortably covers real-world ACLs
// (a handful of named users/groups plus the standard entries); raise it
// if we ever see it hit in practice.
#define FACT_MAX_ACL_ENTRIES 32

// Sentinel used by the kernel for ACL entries that don't carry a uid/gid
// (USER_OBJ, GROUP_OBJ, MASK, OTHER). Kernel defines this as (-1), which
// is 0xFFFFFFFF once read as the unsigned e_id we store it in.
// https://github.com/torvalds/linux/blob/d2c9a99135da931377240942d44f3dea104cedb8/include/uapi/linux/posix_acl.h#L21
#define ACL_UNDEFINED_ID 0xFFFFFFFF

// ACL type, matching the xattr name the change came in on:
// "system.posix_acl_access" vs "system.posix_acl_default". These are the
// only two POSIX ACL xattrs the kernel supports, so a small enum is
// sufficient here rather than keeping the full xattr name around.
typedef enum acl_type_t {
  FACT_ACL_TYPE_ACCESS = 0,
  FACT_ACL_TYPE_DEFAULT = 1,
} acl_type_t;

// Mirrors the kernel's ACL tag bit values so we can encode/compare
// against them without magic numbers, both here and on the Rust side.
// https://github.com/torvalds/linux/blob/d2c9a99135da931377240942d44f3dea104cedb8/include/uapi/linux/posix_acl.h#L28-L33
typedef enum acl_tag_t {
  FACT_ACL_TAG_USER_OBJ = 0x01,
  FACT_ACL_TAG_USER = 0x02,
  FACT_ACL_TAG_GROUP_OBJ = 0x04,
  FACT_ACL_TAG_GROUP = 0x08,
  FACT_ACL_TAG_MASK = 0x10,
  FACT_ACL_TAG_OTHER = 0x20,
} acl_tag_t;

struct acl_entry_t {
  acl_tag_t e_tag;
  unsigned short e_perm;
  unsigned int e_id;
};

typedef enum file_activity_type_t {
  FILE_ACTIVITY_INIT = -1,
  FILE_ACTIVITY_OPEN = 0,
  FILE_ACTIVITY_CREATION,
  FILE_ACTIVITY_UNLINK,
  FILE_ACTIVITY_CHMOD,
  FILE_ACTIVITY_CHOWN,
  FILE_ACTIVITY_RENAME,
  DIR_ACTIVITY_CREATION,
  DIR_ACTIVITY_UNLINK,
  FILE_ACTIVITY_SETXATTR,
  FILE_ACTIVITY_REMOVEXATTR,
  FILE_ACTIVITY_ACL_SET,
  FILE_ACTIVITY_MOUNT,
  FILE_ACTIVITY_UMOUNT,
  FILE_ACTIVITY_MOVE_MOUNT,
} file_activity_type_t;

struct event_t {
  unsigned long timestamp;
  process_t process;
  char filename[PATH_MAX];
  inode_key_t inode;
  inode_key_t parent_inode;
  monitored_t monitored;
  file_activity_type_t type;
  union {
    struct {
      short unsigned int new;
      short unsigned int old;
    } chmod;
    struct {
      struct {
        unsigned int uid;
        unsigned int gid;
      } old, new;
    } chown;
    struct {
      char filename[PATH_MAX];
      inode_key_t inode;
      monitored_t monitored;
    } from;  // Used by events that have two paths (like rename or move_mount).
    struct {
      char name[XATTR_NAME_MAX_LEN];
    } xattr;
    struct {
      unsigned int count;
      acl_type_t acl_type;
      struct acl_entry_t entries[FACT_MAX_ACL_ENTRIES];
    } acl;
  };
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

// Context for correlating mkdir operations
struct mkdir_context_t {
  char path[PATH_MAX];
  inode_key_t parent_inode;
  monitored_t monitored;
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
  struct metrics_by_hook_t path_chmod;
  struct metrics_by_hook_t path_chown;
  struct metrics_by_hook_t path_rename;
  struct metrics_by_hook_t path_mkdir;
  struct metrics_by_hook_t d_instantiate;
  struct metrics_by_hook_t path_rmdir;
  struct metrics_by_hook_t inode_setxattr;
  struct metrics_by_hook_t inode_removexattr;
  struct metrics_by_hook_t inode_set_acl;
  struct metrics_by_hook_t sb_mount;
  struct metrics_by_hook_t sb_umount;
  struct metrics_by_hook_t move_mount;
};
