/*!
 * db_impl.h - database implementation for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on google/leveldb:
 *   Copyright (c) 2011, The LevelDB Authors. All rights reserved.
 *   https://github.com/google/leveldb
 *
 * See LICENSE for more information.
 */

#ifndef LDB_DB_IMPL_H
#define LDB_DB_IMPL_H

#include <stddef.h>
#include <stdint.h>

#include "util/extern.h"
#include "util/options.h"
#include "util/types.h"

/*
 * Types
 */

struct ldb_bloom_s;
struct ldb_batch_s;
struct ldb_comparator_s;
struct ldb_iter_s;
struct ldb_snapshot_s;

typedef struct ldb_s ldb_t;

/*
 * Helpers
 */

/* Sanitize db options. The caller should delete result.info_log if
   it is not equal to src.info_log. */
ldb_dbopt_t
ldb_sanitize_options(const char *dbname,
                     const struct ldb_comparator_s *icmp,
                     const struct ldb_bloom_s *ipolicy,
                     const ldb_dbopt_t *src);

/*
 * API
 */

LDB_EXTERN int
ldb_open(const char *dbname, const ldb_dbopt_t *options, ldb_t **dbptr);

LDB_EXTERN void
ldb_close(ldb_t *db);

LDB_EXTERN int
ldb_get(ldb_t *db, const ldb_slice_t *key,
                   ldb_slice_t *value,
                   const ldb_readopt_t *options);

LDB_EXTERN int
ldb_has(ldb_t *db, const ldb_slice_t *key, const ldb_readopt_t *options);

LDB_EXTERN int
ldb_put(ldb_t *db, const ldb_slice_t *key,
                   const ldb_slice_t *value,
                   const ldb_writeopt_t *options);

LDB_EXTERN int
ldb_del(ldb_t *db, const ldb_slice_t *key, const ldb_writeopt_t *options);

LDB_EXTERN int
ldb_write(ldb_t *db, struct ldb_batch_s *updates,
                     const ldb_writeopt_t *options);

LDB_EXTERN const struct ldb_snapshot_s *
ldb_snapshot(ldb_t *db);

LDB_EXTERN void
ldb_release(ldb_t *db, const struct ldb_snapshot_s *snapshot);

LDB_EXTERN struct ldb_iter_s *
ldb_iterator(ldb_t *db, const ldb_readopt_t *options);

LDB_EXTERN int
ldb_property(ldb_t *db, const char *property, char **value);

LDB_EXTERN void
ldb_approximate_sizes(ldb_t *db, const ldb_range_t *range,
                                 size_t length,
                                 uint64_t *sizes);

LDB_EXTERN void
ldb_compact(ldb_t *db, const ldb_slice_t *begin, const ldb_slice_t *end);

LDB_EXTERN int
ldb_backup(ldb_t *db, const char *name);

#undef ldb_compare

LDB_EXTERN int
ldb_compare(const ldb_t *db, const ldb_slice_t *x, const ldb_slice_t *y);

#ifdef ldb_compare_internal
#  define ldb_compare ldb_compare_internal
#endif

/*
 * Static
 */

LDB_EXTERN int
ldb_repair(const char *dbname, const ldb_dbopt_t *options);

LDB_EXTERN int
ldb_copy(const char *from, const char *to, const ldb_dbopt_t *options);

LDB_EXTERN int
ldb_destroy(const char *dbname, const ldb_dbopt_t *options);

/*
 * Testing
 */

/* Force current memtable contents to be compacted. */
int
ldb_test_compact_memtable(ldb_t *db);

/* Compact any files in the named level that overlap [*begin,*end]. */
void
ldb_test_compact_range(ldb_t *db, int level,
                                  const ldb_slice_t *begin,
                                  const ldb_slice_t *end);

/* Return an internal iterator over the current state of the database.
   The keys of this iterator are internal keys (see format.h).
   The returned iterator should be deleted when no longer needed. */
struct ldb_iter_s *
ldb_test_internal_iterator(ldb_t *db);

/* Return the maximum overlapping data (in bytes) at next level for any
   file at a level >= 1. */
int64_t
ldb_test_max_next_level_overlapping_bytes(ldb_t *db);

/*
 * Internal
 */

/* Record a sample of bytes read at the specified internal key.
   Samples are taken approximately once every LDB_READ_BYTES_PERIOD
   bytes. */
void
ldb_record_read_sample(ldb_t *db, const ldb_slice_t *key);

#endif /* LDB_DB_IMPL_H */
