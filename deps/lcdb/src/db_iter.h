/*!
 * db_iter.h - database iterator for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on google/leveldb:
 *   Copyright (c) 2011, The LevelDB Authors. All rights reserved.
 *   https://github.com/google/leveldb
 *
 * See LICENSE for more information.
 */

#ifndef LDB_DB_ITER_H
#define LDB_DB_ITER_H

#include <stdint.h>
#include "util/extern.h"
#include "util/types.h"

struct ldb_s;
struct ldb_comparator_s;
struct ldb_iter_s;

struct ldb_iter_s *
ldb_dbiter_create(struct ldb_s *db,
                  const struct ldb_comparator_s *user_comparator,
                  struct ldb_iter_s *internal_iter,
                  uint64_t sequence,
                  uint32_t seed);

LDB_EXTERN int
ldb_iter_compare(const struct ldb_iter_s *iter, const ldb_slice_t *key);

LDB_EXTERN void
ldb_iter_seek_ge(struct ldb_iter_s *iter, const ldb_slice_t *target);

LDB_EXTERN void
ldb_iter_seek_gt(struct ldb_iter_s *iter, const ldb_slice_t *target);

LDB_EXTERN void
ldb_iter_seek_le(struct ldb_iter_s *iter, const ldb_slice_t *target);

LDB_EXTERN void
ldb_iter_seek_lt(struct ldb_iter_s *iter, const ldb_slice_t *target);

#endif /* LDB_DB_ITER_H */
