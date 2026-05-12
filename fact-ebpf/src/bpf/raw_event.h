#pragma once

// clang-format off
#include "vmlinux.h"

#include "d_path.h"
#include "bound_path.h"
#include "types.h"

#include <bpf/bpf_helpers.h>
// clang-format on

struct raw_event_t {
  char* buf;
  unsigned short len;
};

#define INIT_RAW_EVENT()                              \
  ({                                                  \
    unsigned int zero = 0;                            \
    struct raw_event_t event = {                      \
        .buf = bpf_map_lookup_elem(&heap_map, &zero), \
        .len = 0,                                     \
    };                                                \
    event;                                            \
  })

#define DECLARE_COPY_UINT(name, decltype)                                                      \
  __always_inline static void raw_event_copy_##name(struct raw_event_t* event, decltype val) { \
    *((decltype*)&event->buf[event->len]) = val;                                               \
    event->len += sizeof(decltype);                                                            \
  }

DECLARE_COPY_UINT(u8, uint8_t);
DECLARE_COPY_UINT(u16, uint16_t);
DECLARE_COPY_UINT(u32, uint32_t);
DECLARE_COPY_UINT(u64, uint64_t);

/**
 * Copy the provided inode information to the event buffer.
 *
 * The serialized blob will be of 2 big endian 32 bits integers, with
 * the inode number first and the device number second.
 *
 * If no inode information is provided, the same space is filled with
 * zeroes for ease of parsing.
 */
__always_inline static void raw_event_copy_inode(struct raw_event_t* event, inode_key_t* val) {
  if (val != NULL) {
    raw_event_copy_u32(event, val->inode);
    raw_event_copy_u32(event, val->dev);
  } else {
    raw_event_copy_u32(event, 0);
    raw_event_copy_u32(event, 0);
  }
}

/**
 * Copy a buffer to the event.
 *
 * The format used for the serialized buffer is as follows:
 * |--|------------|
 * |  ^ begin data
 * ^ data length
 *
 * Data length: 16 bit, big endian integer, number of data bytes held.
 * Data: a blob of bytes with the required data.
 */
__always_inline static long raw_event_copy_buffer(struct raw_event_t* event, const void* buf, uint16_t len) {
  raw_event_copy_u16(event, len);
  long res = bpf_probe_read(&event->buf[event->len], len, buf);
  if (res < 0) {
    return res;
  }
  event->len += len;
  return 0;
}

/**
 * Helper function for encoding a bound_path_t as a buffer in the event.
 *
 * The resulting buffer that is serialized will not be null terminated.
 */
__always_inline static long raw_event_copy_bound_path(struct raw_event_t* event, const struct bound_path_t* const path) {
  // The PATH_LEN_CLAMP is there to convince the verifier we are at
  // most copying 4KB, otherwise it will assume we can add UINT16_MAX
  // bytes and immediately fail, as the event buffer is smaller than
  // that.
  return raw_event_copy_buffer(event, path->path, PATH_LEN_CLAMP(path->len - 1));
}

/**
 * Serialize the comm value for the current task in the event buffer.
 *
 * For simplicity, the comm value is directly copied into the buffer by
 * using the bpf_get_current_comm helper with a fix length of 16.
 *
 * bpf_get_current_comm ensures the copied data is null terminated and
 * padded with zeroes if the comm is smaller than 16 bytes.
 */
__always_inline static long raw_event_copy_comm(struct raw_event_t* event) {
  long res = bpf_get_current_comm((char*)&event->buf[event->len], TASK_COMM_LEN);
  if (res != 0) {
    return res;
  }
  event->len += TASK_COMM_LEN;
  return 0;
}

/**
 * Serialize the result of calling d_path onto the event buffer.
 *
 * The resulting path is encoded as described in raw_event_copy_buffer
 * and is not null terminated.
 */
__always_inline static long raw_event_d_path(struct raw_event_t* event, struct path* path, bool use_bpf_d_path) {
  // Reserve room for the path length
  event->len += 2;
  long res = d_path(path, &event->buf[event->len], PATH_MAX, use_bpf_d_path);
  if (res < 0) {
    return res;
  }

  // Go back and add the length of the path
  uint16_t len = (uint16_t)PATH_LEN_CLAMP(res - 1);
  event->len -= 2;
  raw_event_copy_u16(event, len);

  // Move the buffer past the path
  event->len += len;

  return 0;
}

/**
 * Serialize a null terminated string onto the event buffer.
 *
 * The resulting blob is encoded as described in raw_event_copy_buffer
 * and is not null terminated.
 */
__always_inline static long raw_event_copy_str(struct raw_event_t* event, const char* const str) {
  event->len += 2;
  long len = bpf_probe_read_str(&event->buf[event->len], PATH_MAX, str);
  if (len < 0) {
    return len;
  }

  // Go back and add the length of the path
  event->len -= 2;
  len = PATH_LEN_CLAMP(len - 1);
  raw_event_copy_u16(event, len);

  event->len += len;
  return 0;
}

/**
 * Serialize process arguments onto the event buffer.
 *
 * The kernel stores the process arguments as an array of strings, in
 * case this ends up being larger than our maximum allowed length, we
 * ensure NULL termination to make it easier for userspace to parse.
 */
__always_inline static long raw_event_copy_args(struct raw_event_t* event, const struct task_struct* task) {
  static const uint16_t ARGS_LENGTH_MAX = 0xFFF;
  unsigned long arg_start = task->mm->arg_start;
  unsigned long arg_end = task->mm->arg_end;
  uint16_t arg_len = arg_end - arg_start;
  if (arg_len > ARGS_LENGTH_MAX) {
    arg_len = ARGS_LENGTH_MAX;
  }

  // The final mask on arg_len is simply there to keep the verifier
  // happy.
  long err = raw_event_copy_buffer(event, (const void*)arg_start, (arg_len & ARGS_LENGTH_MAX));
  if (err != 0) {
    bpf_printk("Failed to fill task args");
    return err;
  }

  // Ensure NULL termination of process arguments
  if (arg_len == ARGS_LENGTH_MAX) {
    event->buf[event->len - 1] = 0;
  }

  return 0;
}
