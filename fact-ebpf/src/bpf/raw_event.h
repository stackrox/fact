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

/**
 * Copy a single byte to the event buffer and increment its size.
 */
__always_inline static void raw_event_copy_u8(struct raw_event_t* event, uint8_t val) {
  event->buf[event->len++] = val;
}

/**
 * Copy an unsigned integer in big endian format to the event buffer
 * and increase its size accordingly.
 *
 * Big endian is used in order to make parsing easier in user space by
 * simply rotating a target integer and adding bytes to the end.
 */
__always_inline static void _raw_event_copy_uint(struct raw_event_t* event, uint64_t val, uint8_t size) {
  for (int8_t i = size - 1; i >= 0; i--) {
    uint64_t mask = 0xFFULL << (i * 8);
    uint8_t v = (val & mask) >> (i * 8);
    raw_event_copy_u8(event, v);
  }
}

/**
 * Type safe integer copying.
 */
#define raw_event_copy_uint(event, val) _Generic(val,             \
    uint8_t: raw_event_copy_u8(event, val),                       \
    uint16_t: _raw_event_copy_uint(event, val, sizeof(uint16_t)), \
    uint32_t: _raw_event_copy_uint(event, val, sizeof(uint32_t)), \
    uint64_t: _raw_event_copy_uint(event, val, sizeof(uint64_t)), \
    unsigned long: _raw_event_copy_uint(event, val, sizeof(unsigned long)))

/**
 * Copy a 16 bit integer to the event buffer and increase its size.
 */
__always_inline static void raw_event_copy_u16(struct raw_event_t* event, uint16_t val) {
  raw_event_copy_uint(event, val);
}

/**
 * Copy a 32 bit integer to the event buffer and increase its size.
 */
__always_inline static void raw_event_copy_u32(struct raw_event_t* event, uint32_t val) {
  raw_event_copy_uint(event, val);
}

/**
 * Copy a 64 bit integer to the event buffer and increase its size.
 */
__always_inline static void raw_event_copy_u64(struct raw_event_t* event, uint64_t val) {
  raw_event_copy_uint(event, val);
}

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
    raw_event_copy_uint(event, val->inode);
    raw_event_copy_uint(event, val->dev);
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
  raw_event_copy_uint(event, len);
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
__always_inline static long raw_event_copy_bound_path(struct raw_event_t* event, struct bound_path_t* path) {
  // The & (PATH_MAX - 1) is there to convince the verifier we are at
  // most copying 4KB, otherwise it will assume we can add UINT16_MAX
  // bytes and immediately fail, as the event buffer is smaller than
  // that.
  return raw_event_copy_buffer(event, path->path, (path->len - 1) & (PATH_MAX - 1));
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
  uint16_t len = (uint16_t)res;
  event->len -= 2;
  raw_event_copy_u16(event, len - 1);

  // Move the buffer past the path
  //
  // The & (PATH_MAX - 1) is there to convince the verifier we are at
  // most copying 4KB, otherwise it will assume we can add UINT16_MAX
  // bytes and immediately fail, as the event buffer is smaller than
  // that.
  event->len += ((len - 1) & (PATH_MAX - 1));

  return 0;
}
