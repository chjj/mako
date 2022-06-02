/*!
 * table_cache.h - sstable cache for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on google/leveldb:
 *   Copyright (c) 2011, The LevelDB Authors. All rights reserved.
 *   https://github.com/google/leveldb
 *
 * See LICENSE for more information.
 */

#ifndef LDB_TABLE_CACHE_H
#define LDB_TABLE_CACHE_H

#include <stdint.h>

#include "table/table.h"
#include "util/options.h"
#include "util/types.h"

/*
 * Types
 */

struct ldb_iter_s;

typedef struct ldb_tables_s ldb_tables_t;

/*
 * TableCache
 */

ldb_tables_t *
ldb_tables_create(const char *dbname, const ldb_dbopt_t *options, int entries);

void
ldb_tables_destroy(ldb_tables_t *cache);

/* Return an iterator for the specified file number (the corresponding
 * file length must be exactly "file_size" bytes). If "tableptr" is
 * non-null, also sets "*tableptr" to point to the Table object
 * underlying the returned iterator, or to NULL if no Table object
 * underlies the returned iterator. The returned "*tableptr" object is owned
 * by the cache and should not be deleted, and is valid for as long as the
 * returned iterator is live.
 */
struct ldb_iter_s *
ldb_tables_iterate(ldb_tables_t *cache,
                   const ldb_readopt_t *options,
                   uint64_t file_number,
                   uint64_t file_size,
                   ldb_table_t **tableptr);

/* If a seek to internal key "k" in specified file finds an entry,
   call (*handle_result)(arg, found_key, found_value). */
int
ldb_tables_get(ldb_tables_t *cache,
               const ldb_readopt_t *options,
               uint64_t file_number,
               uint64_t file_size,
               const ldb_slice_t *k,
               void *arg,
               void (*handle_result)(void *,
                                     const ldb_slice_t *,
                                     const ldb_slice_t *));

/* Evict any entry for the specified file number. */
void
ldb_tables_evict(ldb_tables_t *cache, uint64_t file_number);

#endif /* LDB_TABLE_CACHE_H */
