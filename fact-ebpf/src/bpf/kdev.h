#pragma once

// clang-format off
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
// clang-format on

// Most of the code in this file is taken from:
// https://github.com/torvalds/linux/blob/559e608c46553c107dbba19dae0854af7b219400/include/linux/kdev_t.h

#define MINORBITS 20
#define MINORMASK ((1U << MINORBITS) - 1)

#define MAJOR(dev) ((unsigned int)((dev) >> MINORBITS))
#define MINOR(dev) ((unsigned int)((dev) & MINORMASK))

__always_inline static u32 new_encode_dev(dev_t dev) {
  unsigned major = MAJOR(dev);
  unsigned minor = MINOR(dev);
  return (minor & 0xff) | (major << 8) | ((minor & ~0xff) << 12);
}
