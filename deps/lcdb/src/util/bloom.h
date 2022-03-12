/*!
 * bloom.c - bloom filter for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on google/leveldb:
 *   Copyright (c) 2011, The LevelDB Authors. All rights reserved.
 *   https://github.com/google/leveldb
 *
 * See LICENSE for more information.
 */

#ifndef LDB_BLOOM_H
#define LDB_BLOOM_H

#include <stddef.h>
#include <stdint.h>
#include "extern.h"
#include "types.h"

/*
 * Types
 */

typedef struct ldb_bloom_s {
  /* The name of this policy. Note that if the filter encoding
   * changes in an incompatible way, the name returned by this method
   * must be changed. Otherwise, old incompatible filters may be
   * passed to methods of this type.
   */
  const char *name;

  /* keys[0,n-1] contains a list of keys (potentially with duplicates)
   * that are ordered according to the user supplied comparator.
   * Append a filter that summarizes keys[0,n-1] to *dst.
   *
   * Warning: do not change the initial contents of *dst.  Instead,
   * append the newly constructed filter to *dst.
   */
  void (*build)(const struct ldb_bloom_s *bloom,
                ldb_buffer_t *dst,
                const ldb_slice_t *keys,
                size_t length);

  /* "filter" contains the data appended by a preceding call to
   * bloom_add() on this class. This method must return true if
   * the key was in the list of keys passed to bloom_add().
   *
   * This method may return true or false if the key was not on the
   * list, but it should aim to return false with a high probability.
   */
  int (*match)(const struct ldb_bloom_s *bloom,
               const ldb_slice_t *filter,
               const ldb_slice_t *key);

  /* Members specific to bloom filter. */
  size_t bits_per_key;
  size_t k;

  /* For InternalFilterPolicy. */
  const struct ldb_bloom_s *user_policy;

  /* Extra state. */
  void *state;
} ldb_bloom_t;

/*
 * Bloom
 */

/* Return a new filter policy that uses a bloom filter with approximately
 * the specified number of bits per key. A good value for bits_per_key
 * is 10, which yields a filter with ~ 1% false positive rate.
 *
 * Callers must delete the result after any database that is using the
 * result has been closed.
 *
 * Note: if you are using a custom comparator that ignores some parts
 * of the keys being compared, you must not use ldb_bloom_create()
 * and must provide your own filter policy that also ignores the
 * corresponding parts of the keys. For example, if the comparator
 * ignores trailing spaces, it would be incorrect to use a
 * filter policy (like ldb_bloom_create) that does not ignore
 * trailing spaces in keys.
 */
LDB_EXTERN ldb_bloom_t *
ldb_bloom_create(int bits_per_key);

LDB_EXTERN void
ldb_bloom_destroy(ldb_bloom_t *bloom);

void
ldb_bloom_init(ldb_bloom_t *bloom, int bits_per_key);

int
ldb_bloom_name(char *buf, size_t size, const ldb_bloom_t *bloom);

#define ldb_bloom_build(bloom, dst, keys, length) \
  (bloom)->build(bloom, dst, keys, length)

#define ldb_bloom_match(bloom, filter, key) \
  (bloom)->match(bloom, filter, key)

/*
 * Globals
 */

LDB_EXTERN extern const ldb_bloom_t *ldb_bloom_default;

#endif /* LDB_BLOOM_H */
