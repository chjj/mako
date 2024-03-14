/*!
 * types.h - types for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on google/leveldb:
 *   Copyright (c) 2011, The LevelDB Authors. All rights reserved.
 *   https://github.com/google/leveldb
 *
 * See LICENSE for more information.
 */

#ifndef LDB_TYPES_H
#define LDB_TYPES_H

#include <stddef.h>
#include <stdint.h>

typedef struct ldb_slice_s {
  uint8_t *data;
  size_t size;
  size_t alloc;
} ldb_slice_t;

typedef ldb_slice_t ldb_buffer_t;

/* A range of keys. */
typedef struct ldb_range_s {
  ldb_slice_t start; /* Included in the range. */
  ldb_slice_t limit; /* Not included in the range. */
} ldb_range_t;

typedef struct ldb_array_s {
  uint64_t *items;
  size_t length;
  size_t alloc;
} ldb_array_t;

typedef struct ldb_vector_s {
  void **items;
  size_t length;
  size_t alloc;
} ldb_vector_t;

#endif /* LDB_TYPES_H */
