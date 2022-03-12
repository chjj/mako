/*!
 * memcmp.h - memcmp for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on google/leveldb:
 *   Copyright (c) 2011, The LevelDB Authors. All rights reserved.
 *   https://github.com/google/leveldb
 *
 * See LICENSE for more information.
 */

#ifndef LDB_MEMCMP_H
#define LDB_MEMCMP_H

#include <stddef.h>
#include <string.h>
#include "internal.h"

LDB_STATIC int
ldb_memcmp4(const void *x, size_t xn, const void *y, size_t yn) {
  size_t n = xn < yn ? xn : yn;
  int r = n ? memcmp(x, y, n) : 0;

  if (r == 0) {
    if (xn < yn)
      r = -1;
    else if (xn > yn)
      r = +1;
  }

  return r;
}

#endif /* LDB_MEMCMP_H */
