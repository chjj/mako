/*!
 * core.c - core io functions for mako
 * Copyright (c) 2021-2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifdef _WIN32
#  include "core_win_impl.h"
#else
#  include "core_unix_impl.h"
#endif

/*
 * Filesystem
 */

int
btc_fs_read_file(const char *name, unsigned char **dst, size_t *len) {
  btc_fd_t fd = btc_fs_open(name);
  uint8_t *xp = NULL;
  uint64_t size;
  int ret = 0;
  size_t xn;

  if (fd == BTC_INVALID_FD)
    return 0;

  if (!btc_fs_fsize(fd, &size))
    goto fail;

  if (size > (SIZE_MAX >> 1))
    goto fail;

  xn = size;
  xp = malloc(xn + 1);

  if (xp == NULL)
    goto fail;

  if ((size_t)btc_fs_read(fd, xp, xn) != xn)
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
btc_fs_write_file(const char *name, const void *src, size_t len) {
  btc_fd_t fd = btc_fs_create(name);
  int ret = 0;

  if (fd == BTC_INVALID_FD)
    return 0;

  if ((size_t)btc_fs_write(fd, src, len) != len)
    goto fail;

  ret = 1;
fail:
  btc_fs_close(fd);
  return ret;
}

/*
 * Path
 */

int
btc_path_absolutify(char *name, size_t size) {
  char path[BTC_PATH_MAX];
  size_t len;

  if (!btc_path_absolute(path, sizeof(path), name))
    return 0;

  len = strlen(path);

  if (len + 1 > size)
    return 0;

  memcpy(name, path, len + 1);

  return 1;
}

int
btc_path_join(char *zp, size_t zn, const char *xp, const char *yp) {
  size_t xn = strlen(xp);
  size_t yn = strlen(yp);

  if (xn + yn + 2 > zn)
    return 0;

  if (zp != xp) {
    while (*xp)
      *zp++ = *xp++;
  } else {
    zp += xn;
  }

#ifdef _WIN32
  *zp++ = '\\';
#else
  *zp++ = '/';
#endif

  while (*yp)
    *zp++ = *yp++;

  *zp = '\0';

  return 1;
}
