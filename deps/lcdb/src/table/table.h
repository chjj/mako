/*!
 * table.h - sorted string table for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on google/leveldb:
 *   Copyright (c) 2011, The LevelDB Authors. All rights reserved.
 *   https://github.com/google/leveldb
 *
 * See LICENSE for more information.
 */

#ifndef LDB_TABLE_H
#define LDB_TABLE_H

#include <stdint.h>

#include "../util/types.h"

/*
 * Types
 */

struct ldb_dbopt_s;
struct ldb_iter_s;
struct ldb_readopt_s;
struct ldb_rfile_s;

/* A table is a sorted map from strings to strings. Tables are
   immutable and persistent. A table may be safely accessed from
   multiple threads without external synchronization. */
typedef struct ldb_table_s ldb_table_t;

/*
 * Table
 */

/* Attempt to open the table that is stored in bytes [0..file_size)
 * of "file", and read the metadata entries necessary to allow
 * retrieving data from the table.
 *
 * If successful, returns ok and sets "*table" to the newly opened
 * table. The client should delete "*table" when no longer needed.
 * If there was an error while initializing the table, sets "*table"
 * to NULL and returns a non-ok status. Does not take ownership of
 * "*source", but the client must ensure that "source" remains live
 * for the duration of the returned table's lifetime.
 *
 * *file must remain live while this Table is in use.
 */
int
ldb_table_open(const struct ldb_dbopt_s *options,
               struct ldb_rfile_s *file,
               uint64_t size,
               ldb_table_t **table);

void
ldb_table_destroy(ldb_table_t *table);


/* Returns a new iterator over the table contents.
 * The result of create() is initially invalid (caller must
 * call one of the seek methods on the iterator before using it).
 */
struct ldb_iter_s *
ldb_tableiter_create(const ldb_table_t *table,
                     const struct ldb_readopt_s *options);

/* Calls (*handle_result)(arg, ...) with the entry found after a call
 * to seek(key). May not make such a call if filter policy says
 * that key is not present.
 */
int
ldb_table_internal_get(ldb_table_t *table,
                       const struct ldb_readopt_s *options,
                       const ldb_slice_t *k,
                       void *arg,
                       void (*handle_result)(void *,
                                             const ldb_slice_t *,
                                             const ldb_slice_t *));

/* Given a key, return an approximate byte offset in the file where
 * the data for that key begins (or would begin if the key were
 * present in the file). The returned value is in terms of file
 * bytes, and so includes effects like compression of the underlying data.
 * E.g., the approximate offset of the last key in the table will
 * be close to the file length.
 */
uint64_t
ldb_table_approximate_offset(const ldb_table_t *table,
                             const ldb_slice_t *key);

#endif /* LDB_TABLE_H */
