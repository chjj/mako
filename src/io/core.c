/*!
 * core.c - core io functions for libsatoshi
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <io/core.h>

/*
 * High-level Calls
 */

int
btc_fs_read_file(const char *name, void *dst, size_t len) {
  int fd = btc_fs_open(name, BTC_O_RDONLY | BTC_O_SEQUENTIAL, 0);
  int ret = 0;

  if (fd == -1)
    return 0;

  if (!btc_fs_read(fd, dst, len))
    goto fail;

  ret = 1;
fail:
  btc_fs_close(fd);
  return ret;
}

int
btc_fs_write_file(const char *name,
                  uint32_t mode,
                  const void *dst,
                  size_t len) {
  int flags = BTC_O_WRONLY | BTC_O_CREAT | BTC_O_TRUNC;
  int fd = btc_fs_open(name, flags, mode);
  int ret = 0;

  if (fd == -1)
    return 0;

  if (!btc_fs_write(fd, dst, len))
    goto fail;

  ret = 1;
fail:
  btc_fs_close(fd);
  return ret;
}

int
btc_fs_open_lock(const char *name, uint32_t mode) {
  int flags = BTC_O_RDWR | BTC_O_CREAT | BTC_O_TRUNC;
  int fd = btc_fs_open(name, flags, mode);

  if (fd == -1)
    return -1;

  if (!btc_fs_flock(fd, BTC_LOCK_EX)) {
    btc_fs_close(fd);
    return -1;
  }

  return fd;
}

void
btc_fs_close_lock(int fd) {
  btc_fs_flock(fd, BTC_LOCK_UN);
  btc_fs_close(fd);
}

size_t
btc_path_join(char *zp, ...) {
  const char *xp;
  size_t zn = 0;
  va_list ap;

  va_start(ap, zp);

  while ((xp = va_arg(ap, const char *))) {
    while (*xp) {
      *zp++ = *xp++;
      zn++;
    }

    *zp++ = BTC_PATH_SEP;
    zn++;
  }

  *--zp = '\0';
  --zn;

  va_end(ap);

  return zn;
}

int64_t
btc_time_sec(void) {
  btc_timespec_t ts;

  btc_time_get(&ts);

  return ts.tv_sec;
}

int64_t
btc_time_msec(void) {
  btc_timespec_t ts;

  btc_time_get(&ts);

  return (ts.tv_sec * 1000) + (ts.tv_nsec / 1000000);
}

int64_t
btc_time_usec(void) {
  btc_timespec_t ts;

  btc_time_get(&ts);

  return (ts.tv_sec * 1000000) + (ts.tv_nsec / 1000);
}

int64_t
btc_time_nsec(void) {
  btc_timespec_t ts;

  btc_time_get(&ts);

  return (ts.tv_sec * 1000000000) + ts.tv_nsec;
}
