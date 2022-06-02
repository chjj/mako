/*!
 * merger.h - merging iterator for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on google/leveldb:
 *   Copyright (c) 2011, The LevelDB Authors. All rights reserved.
 *   https://github.com/google/leveldb
 *
 * See LICENSE for more information.
 */

#ifndef LDB_MERGER_H
#define LDB_MERGER_H

struct ldb_comparator_s;
struct ldb_iter_s;

/* Return an iterator that provided the union of the data in
 * children[0,n-1]. Takes ownership of the child iterators and
 * will delete them when the result iterator is deleted.
 *
 * The result does no duplicate suppression. I.e., if a particular
 * key is present in K child iterators, it will be yielded K times.
 *
 * REQUIRES: n >= 0
 */
struct ldb_iter_s *
ldb_mergeiter_create(const struct ldb_comparator_s *comparator,
                     struct ldb_iter_s **children,
                     int n);

#endif /* LDB_MERGER_H */
