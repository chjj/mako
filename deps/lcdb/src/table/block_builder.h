/*!
 * block_builder.h - block builder for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on google/leveldb:
 *   Copyright (c) 2011, The LevelDB Authors. All rights reserved.
 *   https://github.com/google/leveldb
 *
 * See LICENSE for more information.
 */

#ifndef LDB_BLOCK_BUILDER_H
#define LDB_BLOCK_BUILDER_H

#include <stddef.h>
#include <stdint.h>

#include "../util/types.h"

/*
 * Types
 */

struct ldb_dbopt_s;

typedef struct ldb_blockbuilder_s {
  const ldb_dbopt_t *options;
  ldb_buffer_t buffer;          /* Destination buffer. */
  ldb_array_t restarts;         /* Restart points (uint32_t). */
  int counter;                  /* Number of entries emitted since restart. */
  int finished;                 /* Has Finish() been called? */
  ldb_buffer_t last_key;
} ldb_blockbuilder_t;

/*
 * Block Builder
 */

void
ldb_blockbuilder_init(ldb_blockbuilder_t *bb,
                      const struct ldb_dbopt_s *options);

void
ldb_blockbuilder_clear(ldb_blockbuilder_t *bb);

/* Reset the contents as if the block builder was just constructed. */
void
ldb_blockbuilder_reset(ldb_blockbuilder_t *bb);

/* REQUIRES: finish() has not been called since the last call to reset(). */
/* REQUIRES: key is larger than any previously added key. */
void
ldb_blockbuilder_add(ldb_blockbuilder_t *bb,
                     const ldb_slice_t *key,
                     const ldb_slice_t *value);

/* Finish building the block and return a slice that refers to the
   block contents.  The returned slice will remain valid for the
   lifetime of this builder or until reset() is called. */
ldb_slice_t
ldb_blockbuilder_finish(ldb_blockbuilder_t *bb);

/* Returns an estimate of the current (uncompressed) size of the block
   we are building. */
size_t
ldb_blockbuilder_size_estimate(const ldb_blockbuilder_t *bb);

/* Return true iff no entries have been added since the last reset(). */
#define ldb_blockbuilder_empty(bb) ((bb)->buffer.size == 0)

#endif /* LDB_BLOCK_BUILDER_H */
