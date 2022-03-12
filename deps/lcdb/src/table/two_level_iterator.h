/*!
 * two_level_iterator.h - two-level iterator for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on google/leveldb:
 *   Copyright (c) 2011, The LevelDB Authors. All rights reserved.
 *   https://github.com/google/leveldb
 *
 * See LICENSE for more information.
 */

#ifndef LDB_TWO_LEVEL_ITERATOR_H
#define LDB_TWO_LEVEL_ITERATOR_H

#include "../util/types.h"

/*
 * Types
 */

struct ldb_iter_s;
struct ldb_readopt_s;

typedef struct ldb_iter_s *(*ldb_blockfunc_f)(void *,
                                              const struct ldb_readopt_s *,
                                              const ldb_slice_t *);

/*
 * Two-Level Iterator
 */

/* Return a new two level iterator. A two-level iterator contains an
 * index iterator whose values point to a sequence of blocks where
 * each block is itself a sequence of key,value pairs. The returned
 * two-level iterator yields the concatenation of all key/value pairs
 * in the sequence of blocks. Takes ownership of "index_iter" and
 * will delete it when no longer needed.
 *
 * Uses a supplied function to convert an index_iter value into
 * an iterator over the contents of the corresponding block.
 */
struct ldb_iter_s *
ldb_twoiter_create(struct ldb_iter_s *index_iter,
                   ldb_blockfunc_f block_function,
                   void *arg,
                   const struct ldb_readopt_s *options);

#endif /* LDB_TWO_LEVEL_ITERATOR_H */
