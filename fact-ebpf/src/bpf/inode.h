#pragma once

// clang-format off
#include "vmlinux.h"

#include "kdev.h"
#include "types.h"
#include "maps.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
// clang-format on

#define BTRFS_SUPER_MAGIC 0x9123683E

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
    case BTRFS_SUPER_MAGIC:
      if (bpf_core_type_exists(struct btrfs_inode)) {
        struct btrfs_inode* btrfs_inode = container_of(inode, struct btrfs_inode, vfs_inode);
        key.inode = inode->i_ino;
        key.dev = BPF_CORE_READ(btrfs_inode, root, anon_dev);
        break;
      }
    // If the btrfs_inode does not exist, most likely it is not
    // supported on the system. Fallback to the generic implementation
    // just in case.
    default:
      key.inode = inode->i_ino;
      key.dev = inode->i_sb->s_dev;
      break;
  }

  // Encode the device so it matches with the result of `stat` in
  // userspace
  key.dev = new_encode_dev(key.dev);

  return key;
}

__always_inline static inode_value_t* inode_get(struct inode_key_t* inode) {
  if (inode == NULL) {
    return NULL;
  }
  return bpf_map_lookup_elem(&inode_map, inode);
}

__always_inline static long inode_remove(struct inode_key_t* inode) {
  return bpf_map_delete_elem(&inode_map, inode);
}

typedef enum inode_monitored_t {
  NOT_MONITORED = 0,
  MONITORED,
} inode_monitored_t;

__always_inline static inode_monitored_t inode_is_monitored(const inode_value_t* inode) {
  if (inode != NULL) {
    return MONITORED;
  }

  return NOT_MONITORED;
}

__always_inline static void inode_copy_or_reset(inode_key_t* dst, const inode_key_t* src) {
  if (dst == NULL) {
    return;
  }

  if (src != NULL) {
    dst->inode = src->inode;
    dst->dev = src->dev;
  } else {
    dst->inode = 0;
    dst->dev = 0;
  }
}
