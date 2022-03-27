/*!
 * two_level_iterator.c - two-level iterator for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on google/leveldb:
 *   Copyright (c) 2011, The LevelDB Authors. All rights reserved.
 *   https://github.com/google/leveldb
 *
 * See LICENSE for more information.
 */

#include <assert.h>
#include <stddef.h>

#include "../util/buffer.h"
#include "../util/internal.h"
#include "../util/options.h"
#include "../util/slice.h"
#include "../util/status.h"

#include "iterator.h"
#include "iterator_wrapper.h"
#include "two_level_iterator.h"

/*
 * Two-Level Iterator
 */

typedef struct ldb_twoiter_s {
  ldb_blockfunc_f block_function;
  void *arg;
  ldb_readopt_t options;
  int status;
  ldb_wrapiter_t index_iter;
  ldb_wrapiter_t data_iter; /* May be NULL. */
  /* If data_iter is non-null, then "data_block_handle_" holds the
    "index_value" passed to block_function to create the data_iter. */
  ldb_buffer_t data_block_handle;
} ldb_twoiter_t;

static int
ldb_twoiter_valid(const ldb_twoiter_t *iter) {
  return ldb_wrapiter_valid(&iter->data_iter);
}

static ldb_slice_t
ldb_twoiter_key(const ldb_twoiter_t *iter) {
  assert(ldb_twoiter_valid(iter));
  return ldb_wrapiter_key(&iter->data_iter);
}

static ldb_slice_t
ldb_twoiter_value(const ldb_twoiter_t *iter) {
  assert(ldb_twoiter_valid(iter));
  return ldb_wrapiter_value(&iter->data_iter);
}

static int
ldb_twoiter_status(const ldb_twoiter_t *iter) {
  int rc;

  if ((rc = ldb_wrapiter_status(&iter->index_iter)))
    return rc;

  if (iter->data_iter.iter != NULL) {
    if ((rc = ldb_wrapiter_status(&iter->data_iter)))
      return rc;
  }

  return iter->status;
}

static void
ldb_twoiter_saverr(ldb_twoiter_t *iter, int status) {
  if (iter->status == LDB_OK && status != LDB_OK)
    iter->status = status;
}

static void
ldb_twoiter_init(ldb_twoiter_t *iter,
               ldb_iter_t *index_iter,
               ldb_blockfunc_f block_function,
               void *arg,
               const ldb_readopt_t *options) {
  iter->block_function = block_function;
  iter->arg = arg;
  iter->options = *options;
  iter->status = LDB_OK;

  ldb_wrapiter_init(&iter->index_iter, index_iter);
  ldb_wrapiter_init(&iter->data_iter, NULL);
  ldb_buffer_init(&iter->data_block_handle);
}

static void
ldb_twoiter_clear(ldb_twoiter_t *iter) {
  ldb_wrapiter_clear(&iter->index_iter);
  ldb_wrapiter_clear(&iter->data_iter);
  ldb_buffer_clear(&iter->data_block_handle);
}

static void
ldb_twoiter_set_data_iter(ldb_twoiter_t *iter, ldb_iter_t *data_iter) {
  if (iter->data_iter.iter != NULL)
    ldb_twoiter_saverr(iter, ldb_wrapiter_status(&iter->data_iter));

  ldb_wrapiter_set(&iter->data_iter, data_iter);
}

static void
ldb_twoiter_init_data_block(ldb_twoiter_t *iter) {
  if (!ldb_wrapiter_valid(&iter->index_iter)) {
    ldb_twoiter_set_data_iter(iter, NULL);
  } else {
    ldb_slice_t handle = ldb_wrapiter_value(&iter->index_iter);

    if (iter->data_iter.iter != NULL
        && ldb_slice_equal(&handle, &iter->data_block_handle)) {
      /* data_iter is already constructed with this iterator, so
         no need to change anything. */
    } else {
      ldb_iter_t *data_iter = iter->block_function(iter->arg,
                                                   &iter->options,
                                                   &handle);

      ldb_buffer_copy(&iter->data_block_handle, &handle);

      ldb_twoiter_set_data_iter(iter, data_iter);
    }
  }
}

static void
ldb_twoiter_skip_forward(ldb_twoiter_t *iter) {
  while (iter->data_iter.iter == NULL || !ldb_wrapiter_valid(&iter->data_iter)) {
    /* Move to next block. */
    if (!ldb_wrapiter_valid(&iter->index_iter)) {
      ldb_twoiter_set_data_iter(iter, NULL);
      return;
    }

    ldb_wrapiter_next(&iter->index_iter);
    ldb_twoiter_init_data_block(iter);

    if (iter->data_iter.iter != NULL)
      ldb_wrapiter_first(&iter->data_iter);
  }
}

static void
ldb_twoiter_skip_backward(ldb_twoiter_t *iter) {
  while (iter->data_iter.iter == NULL || !ldb_wrapiter_valid(&iter->data_iter)) {
    /* Move to next block. */
    if (!ldb_wrapiter_valid(&iter->index_iter)) {
      ldb_twoiter_set_data_iter(iter, NULL);
      return;
    }

    ldb_wrapiter_prev(&iter->index_iter);
    ldb_twoiter_init_data_block(iter);

    if (iter->data_iter.iter != NULL)
      ldb_wrapiter_last(&iter->data_iter);
  }
}

static void
ldb_twoiter_seek(ldb_twoiter_t *iter, const ldb_slice_t *target) {
  ldb_wrapiter_seek(&iter->index_iter, target);
  ldb_twoiter_init_data_block(iter);

  if (iter->data_iter.iter != NULL)
    ldb_wrapiter_seek(&iter->data_iter, target);

  ldb_twoiter_skip_forward(iter);
}

static void
ldb_twoiter_first(ldb_twoiter_t *iter) {
  ldb_wrapiter_first(&iter->index_iter);
  ldb_twoiter_init_data_block(iter);

  if (iter->data_iter.iter != NULL)
    ldb_wrapiter_first(&iter->data_iter);

  ldb_twoiter_skip_forward(iter);
}

static void
ldb_twoiter_last(ldb_twoiter_t *iter) {
  ldb_wrapiter_last(&iter->index_iter);
  ldb_twoiter_init_data_block(iter);

  if (iter->data_iter.iter != NULL)
    ldb_wrapiter_last(&iter->data_iter);

  ldb_twoiter_skip_backward(iter);
}

static void
ldb_twoiter_next(ldb_twoiter_t *iter) {
  assert(ldb_twoiter_valid(iter));
  ldb_wrapiter_next(&iter->data_iter);
  ldb_twoiter_skip_forward(iter);
}

static void
ldb_twoiter_prev(ldb_twoiter_t *iter) {
  assert(ldb_twoiter_valid(iter));
  ldb_wrapiter_prev(&iter->data_iter);
  ldb_twoiter_skip_backward(iter);
}

LDB_ITERATOR_FUNCTIONS(ldb_twoiter);

ldb_iter_t *
ldb_twoiter_create(ldb_iter_t *index_iter,
                   ldb_blockfunc_f block_function,
                   void *arg,
                   const ldb_readopt_t *options) {
  ldb_twoiter_t *iter = ldb_malloc(sizeof(ldb_twoiter_t));

  ldb_twoiter_init(iter, index_iter, block_function, arg, options);

  return ldb_iter_create(iter, &ldb_twoiter_table);
}
