/*!
 * crc32c.h - crc32c for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on google/leveldb:
 *   Copyright (c) 2011, The LevelDB Authors. All rights reserved.
 *   https://github.com/google/leveldb
 *
 * Parts of this software are based on google/crc32c:
 *   Copyright (c) 2017, The CRC32C Authors.
 *   https://github.com/google/crc32c
 *
 * See LICENSE for more information.
 */

#ifndef LDB_CRC32C_H
#define LDB_CRC32C_H

#include <stddef.h>
#include <stdint.h>
#include "internal.h"

/* Initialize crc32c backend. */
int
ldb_crc32c_init(void);

/* Return the crc32c of concat(A, data[0,n-1]) where init_crc is the
 * crc32c of some string A. extend() is often used to maintain the
 * crc32c of a stream of data.
 */
uint32_t
ldb_crc32c_extend(uint32_t z, const uint8_t *xp, size_t xn);

/* Return the crc32c of data[0,n-1]. */
#define ldb_crc32c_value(xp, xn) ldb_crc32c_extend(0, xp, xn)

#define ldb_crc32c_mask_delta UINT32_C(0xa282ead8)

/* Return a masked representation of crc.
 *
 * Motivation: it is problematic to compute the CRC of a string that
 * contains embedded CRCs. Therefore we recommend that CRCs stored
 * somewhere (e.g., in files) should be masked before being stored.
 */
LDB_STATIC uint32_t
ldb_crc32c_mask(uint32_t crc) {
  /* Rotate right by 15 bits and add a constant. */
  return ((crc >> 15) | (crc << 17)) + ldb_crc32c_mask_delta;
}

/* Return the crc whose masked representation is masked_crc. */
LDB_STATIC uint32_t
ldb_crc32c_unmask(uint32_t masked_crc) {
  uint32_t rot = masked_crc - ldb_crc32c_mask_delta;
  return ((rot >> 17) | (rot << 15));
}

#endif /* LDB_CRC32C_H */
