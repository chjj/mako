/*!
 * hash.c - hash for lcdb
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
#include "coding.h"
#include "hash.h"

/*
 * Hash
 */

uint32_t
ldb_hash(const uint8_t *data, size_t size, uint32_t seed) {
  /* Similar to murmur hash. */
  static const uint32_t m = 0xc6a4a793;
  static const uint32_t r = 24;
  uint32_t h = seed ^ (size * m);
  uint32_t w;

  /* Pick up four bytes at a time. */
  while (size >= 4) {
    w = ldb_fixed32_decode(data);

    h += w;
    h *= m;
    h ^= (h >> 16);

    data += 4;
    size -= 4;
  }

  /* Pick up remaining bytes. */
  switch (size) {
    case 3:
      h += ((uint32_t)data[2] << 16);
      /* fallthrough */
    case 2:
      h += ((uint32_t)data[1] << 8);
      /* fallthrough */
    case 1:
      h += data[0];
      h *= m;
      h ^= (h >> r);
      break;
  }

  return h;
}
