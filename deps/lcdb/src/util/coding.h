/*!
 * coding.h - encoding for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on google/leveldb:
 *   Copyright (c) 2011, The LevelDB Authors. All rights reserved.
 *   https://github.com/google/leveldb
 *
 * See LICENSE for more information.
 */

#ifndef LDB_CODING_H
#define LDB_CODING_H

#include <stdint.h>
#include <string.h>
#include "internal.h"
#include "types.h"

/*
 * Coding
 */

LDB_UNUSED static void
ldb_fixed32_encode(uint8_t *zp, uint32_t x) {
  zp[0] = (uint8_t)(x >>  0);
  zp[1] = (uint8_t)(x >>  8);
  zp[2] = (uint8_t)(x >> 16);
  zp[3] = (uint8_t)(x >> 24);
}

LDB_UNUSED static uint32_t
ldb_fixed32_decode(const uint8_t *xp) {
  return ((uint32_t)xp[0] <<  0)
       | ((uint32_t)xp[1] <<  8)
       | ((uint32_t)xp[2] << 16)
       | ((uint32_t)xp[3] << 24);
}

LDB_UNUSED static void
ldb_fixed64_encode(uint8_t *zp, uint64_t x) {
  zp[0] = (uint8_t)(x >>  0);
  zp[1] = (uint8_t)(x >>  8);
  zp[2] = (uint8_t)(x >> 16);
  zp[3] = (uint8_t)(x >> 24);
  zp[4] = (uint8_t)(x >> 32);
  zp[5] = (uint8_t)(x >> 40);
  zp[6] = (uint8_t)(x >> 48);
  zp[7] = (uint8_t)(x >> 56);
}

LDB_UNUSED static uint64_t
ldb_fixed64_decode(const uint8_t *xp) {
  return ((uint64_t)xp[0] <<  0)
       | ((uint64_t)xp[1] <<  8)
       | ((uint64_t)xp[2] << 16)
       | ((uint64_t)xp[3] << 24)
       | ((uint64_t)xp[4] << 32)
       | ((uint64_t)xp[5] << 40)
       | ((uint64_t)xp[6] << 48)
       | ((uint64_t)xp[7] << 56);
}

LDB_UNUSED static uint8_t *
ldb_fixed32_write(uint8_t *zp, uint32_t x) {
  *zp++ = (uint8_t)(x >>  0);
  *zp++ = (uint8_t)(x >>  8);
  *zp++ = (uint8_t)(x >> 16);
  *zp++ = (uint8_t)(x >> 24);
  return zp;
}

LDB_UNUSED static int
ldb_fixed32_read(uint32_t *z, const uint8_t **xp, size_t *xn) {
  if (*xn < 4)
    return 0;

  *z = ldb_fixed32_decode(*xp);

  *xp += 4;
  *xn -= 4;

  return 1;
}

LDB_UNUSED static int
ldb_fixed32_slurp(uint32_t *z, ldb_slice_t *x) {
  return ldb_fixed32_read(z, (const uint8_t **)&x->data, &x->size);
}

LDB_UNUSED static uint8_t *
ldb_fixed64_write(uint8_t *zp, uint64_t x) {
  *zp++ = (uint8_t)(x >>  0);
  *zp++ = (uint8_t)(x >>  8);
  *zp++ = (uint8_t)(x >> 16);
  *zp++ = (uint8_t)(x >> 24);
  *zp++ = (uint8_t)(x >> 32);
  *zp++ = (uint8_t)(x >> 40);
  *zp++ = (uint8_t)(x >> 48);
  *zp++ = (uint8_t)(x >> 56);
  return zp;
}

LDB_UNUSED static int
ldb_fixed64_read(uint64_t *z, const uint8_t **xp, size_t *xn) {
  if (*xn < 8)
    return 0;

  *z = ldb_fixed64_decode(*xp);

  *xp += 8;
  *xn -= 8;

  return 1;
}

LDB_UNUSED static int
ldb_fixed64_slurp(uint64_t *z, ldb_slice_t *x) {
  return ldb_fixed64_read(z, (const uint8_t **)&x->data, &x->size);
}

LDB_UNUSED static size_t
ldb_varint32_size(uint32_t x) {
  if (x < (1 << 7))
    return 1;

  if (x < (1 << 14))
    return 2;

  if (x < (1 << 21))
    return 3;

  if (x < (1 << 28))
    return 4;

  return 5;
}

LDB_UNUSED static uint8_t *
ldb_varint32_write(uint8_t *zp, uint32_t x) {
  static const uint32_t B = 128;

  if (x < (1 << 7)) {
    *zp++ = x;
  } else if (x < (1 << 14)) {
    *zp++ = x | B;
    *zp++ = x >> 7;
  } else if (x < (1 << 21)) {
    *zp++ = x | B;
    *zp++ = (x >> 7) | B;
    *zp++ = x >> 14;
  } else if (x < (1 << 28)) {
    *zp++ = x | B;
    *zp++ = (x >> 7) | B;
    *zp++ = (x >> 14) | B;
    *zp++ = x >> 21;
  } else {
    *zp++ = x | B;
    *zp++ = (x >> 7) | B;
    *zp++ = (x >> 14) | B;
    *zp++ = (x >> 21) | B;
    *zp++ = x >> 28;
  }

  return zp;
}

LDB_UNUSED static int
ldb_varint32_read(uint32_t *z, const uint8_t **xp, size_t *xn) {
  uint32_t result, shift;

  if (LIKELY(*xn > 0)) {
    result = **xp;

    if ((result & 128) == 0) {
      *xp += 1;
      *xn -= 1;
      *z = result;
      return 1;
    }
  }

  result = 0;

  for (shift = 0; shift <= 28 && *xn > 0; shift += 7) {
    uint32_t byte = **xp;

    *xp += 1;
    *xn -= 1;

    if (byte & 128) {
      result |= ((byte & 127) << shift);
    } else {
      result |= (byte << shift);
      *z = result;
      return 1;
    }
  }

  *z = 0;

  return 0;
}

LDB_UNUSED static int
ldb_varint32_slurp(uint32_t *z, ldb_slice_t *x) {
  return ldb_varint32_read(z, (const uint8_t **)&x->data, &x->size);
}

LDB_UNUSED static size_t
ldb_varint64_size(uint64_t x) { /* VarintLength */
  size_t len = 1;

  while (x >= 128) {
    x >>= 7;
    len++;
  }

  return len;
}

LDB_UNUSED static uint8_t *
ldb_varint64_write(uint8_t *zp, uint64_t x) {
  static const uint64_t B = 128;

  while (x >= B) {
    *zp++ = x | B;
    x >>= 7;
  }

  *zp++ = x;

  return zp;
}

LDB_UNUSED static int
ldb_varint64_read(uint64_t *z, const uint8_t **xp, size_t *xn) {
  uint64_t result = 0;
  uint32_t shift;

  for (shift = 0; shift <= 63 && *xn > 0; shift += 7) {
    uint64_t byte = **xp;

    *xp += 1;
    *xn -= 1;

    if (byte & 128) {
      result |= ((byte & 127) << shift);
    } else {
      result |= (byte << shift);
      *z = result;
      return 1;
    }
  }

  *z = 0;

  return 0;
}

LDB_UNUSED static int
ldb_varint64_slurp(uint64_t *z, ldb_slice_t *x) {
  return ldb_varint64_read(z, (const uint8_t **)&x->data, &x->size);
}

LDB_UNUSED static uint8_t *
ldb_raw_write(uint8_t *zp, const uint8_t *xp, size_t xn) {
  if (xn > 0)
    memcpy(zp, xp, xn);

  return zp + xn;
}

LDB_UNUSED static int
ldb_raw_read(uint8_t *zp, size_t zn,
            const uint8_t **xp, size_t *xn) {
  if (*xn < zn)
    return 0;

  if (zn > 0) {
    memcpy(zp, *xp, zn);
    *xp += zn;
    *xn -= zn;
  }

  return 1;
}

LDB_UNUSED static int
ldb_zraw_read(const uint8_t **zp, size_t zn,
              const uint8_t **xp, size_t *xn) {
  if (*xn < zn)
    return 0;

  *zp = *xp;
  *xp += zn;
  *xn -= zn;

  return 1;
}

LDB_UNUSED static uint8_t *
ldb_padding_write(uint8_t *zp, size_t zn) {
  if (zn > 0)
    memset(zp, 0, zn);

  return zp + zn;
}

#endif /* LDB_CODING_H */
