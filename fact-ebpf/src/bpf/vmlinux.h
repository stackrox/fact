#pragma once

#if defined(__TARGET_ARCH_x86)
#  include "vmlinux/x86_64.h"
#elif defined(__TARGET_ARCH_arm64)
#  include "vmlinux/aarch64.h"
#else
#  error "Unknown target"
#endif
