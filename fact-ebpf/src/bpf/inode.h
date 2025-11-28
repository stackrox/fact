#pragma once

// clang-format off
#include "vmlinux.h"

#include "types.h"
#include "maps.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
// clang-format on

typedef enum inode_monitored_t {
  NOT_MONITORED = 0,
  MONITORED,
  PARENT_MONITORED,
} inode_monitored_t;

#define BTRFS_SUPER_MAGIC 0x9123683E
#define BTRFS_MAGIC 0x4D5F53665248425FULL

/**
 * Retrieve the inode and device numbers and return them as a new key.
 *
 * Different filesystems may `stat` files in different ways, if support
 * for a new filesystem is needed, add it here.
 *
 * Most Linux filesystems use the following generic function to fill
 * these fields when running `stat`:
 * https://github.com/torvalds/linux/blob/7d0a66e4bb9081d75c82ec4957c50034cb0ea449/fs/stat.c#L82
 *
 * The method used to retrieve the device is different in btrfs and can
 * be found here:
 * https://github.com/torvalds/linux/blob/7d0a66e4bb9081d75c82ec4957c50034cb0ea449/fs/btrfs/inode.c#L8038
 */
__always_inline static inode_key_t inode_to_key(struct inode* inode) {
  inode_key_t key = {0};
  if (inode == NULL) {
    return key;
  }

  unsigned long magic = inode->i_sb->s_magic;
  switch (magic) {
    case BTRFS_MAGIC:
    case BTRFS_SUPER_MAGIC: {
      struct btrfs_inode* btrfs_inode = container_of(inode, struct btrfs_inode, vfs_inode);
      key.inode = inode->i_ino;
      key.dev = BPF_CORE_READ(btrfs_inode, root, anon_dev);
    } break;
    default:
      key.inode = inode->i_ino;
      key.dev = inode->i_sb->s_dev;
      break;
  }

  return key;
}

__always_inline static inode_value_t* inode_get(struct inode_key_t* inode) {
  if (inode == NULL) {
    return NULL;
  }
  return bpf_map_lookup_elem(&inode_map, inode);
}

__always_inline static const inode_value_t* inode_insert(struct inode_key_t* key) {
  static const inode_value_t zero = 0;
  if (bpf_map_update_elem(&inode_map, key, &zero, BPF_ANY) != 0) {
    return NULL;
  } else {
    return &zero;
  }
}

__always_inline static void inode_remove(struct inode_key_t* key) {
  bpf_map_delete_elem(&inode_map, key);
}

__always_inline static inode_monitored_t inode_is_monitored(const inode_value_t* inode, const inode_value_t* parent) {
  if (inode != NULL) {
    return MONITORED;
  }

  if (parent != NULL) {
    return PARENT_MONITORED;
  }

  return NOT_MONITORED;
}

__always_inline static void inode_reset(inode_key_t* inode) {
  inode->inode = 0;
  inode->dev = 0;
}

__always_inline static void inode_copy_or_reset(inode_key_t* dst, const inode_key_t* src) {
  if (dst == NULL) {
    return;
  }

  if (src != NULL) {
    dst->inode = src->inode;
    dst->dev = src->dev;
  } else {
    inode_reset(dst);
  }
}

/**
 * Add the file to the inode map.
 *
 * Userspace will verify if the file is monitored and remove it if it is
 * not.
 *
 */
__always_inline static const inode_value_t* inode_new(struct inode* inode) {
  inode_key_t key = inode_to_key(inode);
  return inode_insert(&key);
}
