/*!
 * iterator_wrapper.h - iterator wrapper for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on google/leveldb:
 *   Copyright (c) 2011, The LevelDB Authors. All rights reserved.
 *   https://github.com/google/leveldb
 *
 * See LICENSE for more information.
 */

#ifndef LDB_ITERATOR_WRAPPER_H
#define LDB_ITERATOR_WRAPPER_H

#include <assert.h>
#include <stddef.h>

#include "../util/internal.h"
#include "../util/types.h"

#include "iterator.h"

/* A internal wrapper class with an interface similar to Iterator that
   caches the valid() and key() results for an underlying iterator.
   This can help avoid virtual function calls and also gives better
   cache locality. */

/*
 * Iterator Wrapper
 */

typedef struct ldb_wrapiter_s {
  ldb_iter_t *iter;
  int valid;
  ldb_slice_t key;
} ldb_wrapiter_t;

LDB_UNUSED static void
ldb_wrapiter_update(ldb_wrapiter_t *wrap) {
  wrap->valid = ldb_iter_valid(wrap->iter);

  if (wrap->valid)
    wrap->key = ldb_iter_key(wrap->iter);
}

LDB_UNUSED static void
ldb_wrapiter_init(ldb_wrapiter_t *wrap, ldb_iter_t *iter) {
  wrap->iter = iter;
  wrap->valid = 0;

  ldb_slice_init(&wrap->key);

  if (wrap->iter != NULL)
    ldb_wrapiter_update(wrap);
}

LDB_UNUSED static void
ldb_wrapiter_clear(ldb_wrapiter_t *wrap) {
  if (wrap->iter != NULL)
    ldb_iter_destroy(wrap->iter);
}

/* Takes ownership of "iter" and will delete it when destroyed, or
   when Set() is invoked again. */
LDB_UNUSED static void
ldb_wrapiter_set(ldb_wrapiter_t *wrap, ldb_iter_t *iter) {
  if (wrap->iter != NULL)
    ldb_iter_destroy(wrap->iter);

  wrap->iter = iter;
  wrap->valid = 0;

  if (wrap->iter != NULL)
    ldb_wrapiter_update(wrap);
}

LDB_UNUSED static int
ldb_wrapiter_valid(const ldb_wrapiter_t *wrap) {
  return wrap->valid;
}

LDB_UNUSED static void
ldb_wrapiter_seek(ldb_wrapiter_t *wrap, const ldb_slice_t *k) {
  assert(wrap->iter != NULL);
  ldb_iter_seek(wrap->iter, k);
  ldb_wrapiter_update(wrap);
}

LDB_UNUSED static void
ldb_wrapiter_first(ldb_wrapiter_t *wrap) {
  assert(wrap->iter != NULL);
  ldb_iter_first(wrap->iter);
  ldb_wrapiter_update(wrap);
}

LDB_UNUSED static void
ldb_wrapiter_last(ldb_wrapiter_t *wrap) {
  assert(wrap->iter != NULL);
  ldb_iter_last(wrap->iter);
  ldb_wrapiter_update(wrap);
}

LDB_UNUSED static void
ldb_wrapiter_next(ldb_wrapiter_t *wrap) {
  assert(wrap->iter != NULL);
  ldb_iter_next(wrap->iter);
  ldb_wrapiter_update(wrap);
}

LDB_UNUSED static void
ldb_wrapiter_prev(ldb_wrapiter_t *wrap) {
  assert(wrap->iter != NULL);
  ldb_iter_prev(wrap->iter);
  ldb_wrapiter_update(wrap);
}

LDB_UNUSED static ldb_slice_t
ldb_wrapiter_key(const ldb_wrapiter_t *wrap) {
  assert(ldb_wrapiter_valid(wrap));
  return wrap->key;
}

LDB_UNUSED static ldb_slice_t
ldb_wrapiter_value(const ldb_wrapiter_t *wrap) {
  assert(ldb_wrapiter_valid(wrap));
  return ldb_iter_value(wrap->iter);
}

LDB_UNUSED static int
ldb_wrapiter_status(const ldb_wrapiter_t *wrap) {
  assert(wrap->iter != NULL);
  return ldb_iter_status(wrap->iter);
}

#endif /* LDB_ITERATOR_WRAPPER_H */
