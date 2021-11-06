/*!
 * core.c - core io functions for libsatoshi
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <io/core.h>

/*
 * Filesystem
 */

int
btc_fs_read_file(const char *name, void *dst, size_t len) {
  int flags = BTC_O_RDONLY | BTC_O_SEQUENTIAL;
  int fd = btc_fs_open(name, flags, 0);
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
                  const void *src,
                  size_t len) {
  int flags = BTC_O_WRONLY | BTC_O_CREAT | BTC_O_TRUNC;
  int fd = btc_fs_open(name, flags, mode);
  int ret = 0;

  if (fd == -1)
    return 0;

  if (!btc_fs_write(fd, src, len))
    goto fail;

  ret = 1;
fail:
  btc_fs_close(fd);
  return ret;
}

int
btc_fs_alloc_file(unsigned char **dst, size_t *len, const char *name) {
  int flags = BTC_O_RDONLY | BTC_O_SEQUENTIAL;
  int fd = btc_fs_open(name, flags, 0);
  uint8_t *xp = NULL;
  btc_stat_t stat;
  int ret = 0;
  size_t xn;

  if (fd == -1)
    return 0;

  if (!btc_fs_fstat(fd, &stat))
    goto fail;

  if ((uint64_t)stat.st_size > (SIZE_MAX >> 1))
    goto fail;

  xn = stat.st_size;

  if (xn == 0)
    goto fail;

  xp = malloc(xn);

  if (xp == NULL)
    goto fail;

  if (!btc_fs_read(fd, xp, xn))
    goto fail;

  *dst = xp;
  *len = xn;

  xp = NULL;
  ret = 1;
fail:
  btc_fs_close(fd);

  if (xp != NULL)
    free(xp);

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

/*
 * Path
 */

int
btc_path_join(char *buf, size_t size, ...) {
  char *zp = buf;
  size_t zn = 0;
  const char *xp;
  va_list ap;

  va_start(ap, size);

  while ((xp = va_arg(ap, const char *))) {
    zn += strlen(xp) + 1;

    if (zn > size) {
      va_end(ap);
      return 0;
    }

    while (*xp)
      *zp++ = *xp++;

    *zp++ = BTC_PATH_SEP;
  }

  if (zn > 0)
    zp--;

  *zp = '\0';

  va_end(ap);

  return 1;
}
