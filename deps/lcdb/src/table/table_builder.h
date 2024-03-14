/*!
 * table_builder.h - sorted string table builder for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on google/leveldb:
 *   Copyright (c) 2011, The LevelDB Authors. All rights reserved.
 *   https://github.com/google/leveldb
 *
 * See LICENSE for more information.
 */

#ifndef LDB_TABLE_BUILDER_H
#define LDB_TABLE_BUILDER_H

#include <stdint.h>

#include "../util/types.h"

/*
 * Types
 */

struct ldb_dbopt_s;
struct ldb_wfile_s;

typedef struct ldb_tablegen_s ldb_tablegen_t;

/*
 * TableBuilder
 */

/* Create a builder that will store the contents of the table it is
 * building in *file. Does not close the file. It is up to the
 * caller to close the file after calling finish().
 */
ldb_tablegen_t *
ldb_tablegen_create(const struct ldb_dbopt_s *options,
                    struct ldb_wfile_s *file);

/* REQUIRES: Either finish() or abandon() has been called. */
void
ldb_tablegen_destroy(ldb_tablegen_t *tb);

/* Add key,value to the table being constructed. */
/* REQUIRES: key is after any previously added key according to comparator. */
/* REQUIRES: finish(), abandon() have not been called */
void
ldb_tablegen_add(ldb_tablegen_t *tb,
                 const ldb_slice_t *key,
                 const ldb_slice_t *value);

/* Advanced operation: flush any buffered key/value pairs to file.
 * Can be used to ensure that two adjacent entries never live in
 * the same data block. Most clients should not need to use this method.
 * REQUIRES: finish(), abandon() have not been called
 */
void
ldb_tablegen_flush(ldb_tablegen_t *tb);

/* Finish building the table. Stops using the file passed to the
 * constructor after this function returns.
 * REQUIRES: finish(), abandon() have not been called
 */
int
ldb_tablegen_finish(ldb_tablegen_t *tb);

/* Indicate that the contents of this builder should be abandoned. Stops
 * using the file passed to the constructor after this function returns.
 * If the caller is not going to call finish(), it must call abandon()
 * before destroying this builder.
 * REQUIRES: finish(), abandon() have not been called
 */
void
ldb_tablegen_abandon(ldb_tablegen_t *tb);

/* Return non-ok iff some error has been detected. */
int
ldb_tablegen_status(const ldb_tablegen_t *tb);

/* Number of calls to add() so far. */
uint64_t
ldb_tablegen_entries(const ldb_tablegen_t *tb);

/* Size of the file generated so far. If invoked after a successful
   finish() call, returns the size of the final generated file. */
uint64_t
ldb_tablegen_size(const ldb_tablegen_t *tb);

#endif /* LDB_TABLE_BUILDER_H */
