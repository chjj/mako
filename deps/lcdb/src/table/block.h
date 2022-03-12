/*!
 * block.h - block for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on google/leveldb:
 *   Copyright (c) 2011, The LevelDB Authors. All rights reserved.
 *   https://github.com/google/leveldb
 *
 * See LICENSE for more information.
 */

#ifndef LDB_BLOCK_H
#define LDB_BLOCK_H

#include <stddef.h>
#include <stdint.h>

/*
 * Types
 */

struct ldb_blockcontents_s;
struct ldb_comparator_s;
struct ldb_iter_s;

typedef struct ldb_block_s {
  const uint8_t *data;
  size_t size;
  uint32_t restart_offset;  /* Offset in data of restart array. */
  int owned;                /* Block owns data[]. */
} ldb_block_t;

/*
 * Block
 */

ldb_block_t *
ldb_block_create(const struct ldb_blockcontents_s *contents);

void
ldb_block_destroy(ldb_block_t *block);

void
ldb_block_init(ldb_block_t *block, const struct ldb_blockcontents_s *contents);

void
ldb_block_clear(ldb_block_t *block);

/*
 * Block Iterator
 */

struct ldb_iter_s *
ldb_blockiter_create(const ldb_block_t *block,
                     const struct ldb_comparator_s *comparator);

#endif /* LDB_BLOCK_H */
