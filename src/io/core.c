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
btc_fs_read_file(const char *name, void *dst, size_t len) {
  btc_fd_t fd = btc_fs_open(name);
  int ret = 0;

  if (fd == BTC_INVALID_FD)
    return 0;

  if (!btc_fs_read(fd, dst, len))
    goto fail;

  ret = 1;
fail:
  btc_fs_close(fd);
  return ret;
}

int
btc_fs_write_file(const char *name, const void *src, size_t len) {
  btc_fd_t fd = btc_fs_create(name);
  int ret = 0;

  if (fd == BTC_INVALID_FD)
    return 0;

  if (!btc_fs_write(fd, src, len))
    goto fail;

  ret = 1;
fail:
  btc_fs_close(fd);
  return ret;
}

int
btc_fs_alloc_file(const char *name, unsigned char **dst, size_t *len) {
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

/*
 * Path
 */

static int
btc_path_is_absolute(const char *path) {
#ifdef _WIN32
  if (path[0] == '\0')
    return 0;

  if (path[0] == '/' || path[0] == '\\')
    return 1;

  if (path[0] >= 'A' && path[0] <= 'Z' && path[1] == ':')
    return path[2] == '/' || path[2] == '\\';

  if (path[0] >= 'a' && path[0] <= 'z' && path[1] == ':')
    return path[2] == '/' || path[2] == '\\';

  return 0;
#else
  return path[0] == '/';
#endif
}

int
btc_path_absolutify(char *buf, size_t size) {
  char tp[BTC_PATH_MAX];
  size_t tn;

  if (btc_path_is_absolute(buf))
    return 1;

  if (!btc_path_absolute(tp, sizeof(tp), buf))
    return 0;

  tn = strlen(tp);

  if (tn + 1 > size)
    return 0;

  memcpy(buf, tp, tn + 1);

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

int
btc_path_resolve(char *zp, size_t zn, const char *xp, const char *yp) {
  char tp[BTC_PATH_MAX];

  if (btc_path_is_absolute(xp))
    return btc_path_join(zp, zn, xp, yp);

  if (!btc_path_absolute(tp, sizeof(tp), xp))
    return 0;

  return btc_path_join(zp, zn, tp, yp);
}
