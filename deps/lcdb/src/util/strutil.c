/*!
 * strutil.c - string utilities for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on google/leveldb:
 *   Copyright (c) 2011, The LevelDB Authors. All rights reserved.
 *   https://github.com/google/leveldb
 *
 * See LICENSE for more information.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "strutil.h"

/*
 * String
 */

int
ldb_size_int(uint64_t x) {
  int n = 0;

  do {
    n++;
    x /= 10;
  } while (x != 0);

  return n;
}

int
ldb_encode_int(char *zp, uint64_t x, int pad) {
  int n = ldb_size_int(x);
  int i;

  if (n < pad)
    n = pad;

  zp[n] = '\0';

  for (i = n - 1; i >= 0; i--) {
    zp[i] = '0' + (int)(x % 10);
    x /= 10;
  }

  return n;
}

int
ldb_decode_int(uint64_t *z, const char **xp) {
  const int last = '0' + (int)(UINT64_MAX % 10);
  const uint64_t limit = UINT64_MAX / 10;
  const char *sp = *xp;
  uint64_t x = 0;

  while (*sp) {
    int ch = *sp;

    if (ch < '0' || ch > '9')
      break;

    if (x > limit || (x == limit && ch > last))
      return 0;

    x *= 10;
    x += (ch - '0');

    sp++;
  }

  if (sp == *xp)
    return 0;

  *xp = sp;
  *z = x;

  return 1;
}

int
ldb_starts_with(const char *xp, const char *yp) {
  while (*xp && *xp == *yp) {
    xp++;
    yp++;
  }

  return *yp == 0;
}

char *
ldb_basename(const char *fname) {
#ifdef _WIN32
  size_t len = strlen(fname);

  while (len > 0) {
    if (fname[len - 1] == '/' || fname[len - 1] == '\\')
      break;

    len--;
  }

  return (char *)fname + len;
#else
  const char *base = strrchr(fname, '/');

  if (base == NULL)
    base = fname;
  else
    base += 1;

  return (char *)base;
#endif
}

int
ldb_dirname(char *buf, size_t size, const char *fname) {
  const char *base = ldb_basename(fname);
  size_t len;

  if (base == fname) {
    if (size < 2)
      return 0;

    *buf++ = '.';
    *buf++ = '\0';
  } else {
    len = base - fname;

#ifdef _WIN32
    while (len > 0 && (fname[len - 1] == '/' || fname[len - 1] == '\\'))
      len -= 1;
#else
    while (len > 0 && fname[len - 1] == '/')
      len -= 1;
#endif

    if (len == 0)
      len = 1;

    if (len + 1 > size)
      return 0;

    if (buf != fname)
      memcpy(buf, fname, len);

    buf[len] = '\0';
  }

  return 1;
}

int
ldb_join(char *zp, size_t zn, const char *xp, const char *yp) {
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
