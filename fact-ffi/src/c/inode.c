#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <linux/bpf.h>
#include <sys/syscall.h>
#include <sys/types.h>

int32_t add_path(int32_t map_fd, const char* path, const char* host_path) {
  int fd = open(path, O_RDONLY);
  if (fd <= 0) {
    fprintf(stderr, "%s:%d - open error: %d\n", __FILE__, __LINE__, errno);
    return errno;
  }

  char buf[4096];
  snprintf(buf, 4096, "%s", host_path);

  union bpf_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.map_fd = map_fd;
  attr.key = (unsigned long long)&fd;
  attr.value = (unsigned long long)buf;
  attr.flags = BPF_NOEXIST;

  long res = syscall(SYS_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
  if (res == -EEXIST) {
    res = 0;
  }

  close(fd);
  return res;
}
