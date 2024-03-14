/*!
 * comparator.h - comparator for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on google/leveldb:
 *   Copyright (c) 2011, The LevelDB Authors. All rights reserved.
 *   https://github.com/google/leveldb
 *
 * See LICENSE for more information.
 */

#ifndef LDB_COMPARATOR_H
#define LDB_COMPARATOR_H

#include <stddef.h>
#include "extern.h"
#include "types.h"

/*
 * Types
 */

/* A comparator object provides a total order across slices that are
 * used as keys in an sstable or a database. A comparator implementation
 * must be thread-safe since the implementation may invoke its methods
 * concurrently from multiple threads.
 */
typedef struct ldb_comparator_s {
  /* The name of the comparator. Used to check for comparator
   * mismatches (i.e., a database created with one comparator is
   * accessed using a different comparator.
   *
   * The client of this package should switch to a new name whenever
   * the comparator implementation changes in a way that will cause
   * the relative ordering of any two keys to change.
   *
   * Names starting with "leveldb." are reserved and should not be used
   * by any clients of this package.
   */
  const char *name;

  /* Three-way comparison. Returns value:
   *   < 0 iff "a" < "b",
   *   == 0 iff "a" == "b",
   *   > 0 iff "a" > "b"
   */
  int (*compare)(const struct ldb_comparator_s *,
                 const ldb_slice_t *,
                 const ldb_slice_t *);

  /* Advanced functions: these are used to reduce the space requirements
     for internal data structures like index blocks. */

  /* If *start < limit, changes *start to a short string in [start,limit).
     Simple comparator implementations may return with *start unchanged,
     i.e., an implementation of this method that does nothing is correct. */
  void (*shortest_separator)(const struct ldb_comparator_s *,
                             ldb_buffer_t *,
                             const ldb_slice_t *);

  /* Changes *key to a short string >= *key.
     Simple comparator implementations may return with *key unchanged,
     i.e., an implementation of this method that does nothing is correct. */
  void (*short_successor)(const struct ldb_comparator_s *, ldb_buffer_t *);

  /* For InternalKeyComparator. */
  const struct ldb_comparator_s *user_comparator;

  /* Extra state. */
  void *state;
} ldb_comparator_t;

/*
 * Macros
 */

#define ldb_compare_internal(cmp, x, y) (cmp)->compare(cmp, x, y)
#define ldb_compare ldb_compare_internal

#define ldb_shortest_separator(cmp, start, limit) do { \
  if ((cmp)->shortest_separator != NULL)               \
    (cmp)->shortest_separator(cmp, start, limit);      \
} while (0)

#define ldb_short_successor(cmp, key) do { \
  if ((cmp)->short_successor != NULL)      \
    (cmp)->short_successor(cmp, key);      \
} while (0)

/*
 * Globals
 */

#ifdef _WIN32
LDB_EXTERN const ldb_comparator_t *ldb_comparator_import(void);
#define ldb_bytewise_comparator (ldb_comparator_import())
#else
LDB_EXTERN extern const ldb_comparator_t *ldb_bytewise_comparator;
#endif

#endif /* LDB_COMPARATOR_H */
