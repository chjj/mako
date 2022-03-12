/*!
 * iterator.c - iterator for lcdb
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

#include "../util/internal.h"
#include "../util/types.h"

#include "iterator.h"

/*
 * Iterator
 */

static void
ldb_iter_init(ldb_iter_t *iter, void *ptr, const ldb_itertbl_t *table) {
  iter->ptr = ptr;
  iter->cleanup_head.func = NULL;
  iter->cleanup_head.next = NULL;
  iter->table = table;
}

static void
ldb_iter_clear(ldb_iter_t *iter) {
  if (!ldb_cleanup_empty(&iter->cleanup_head)) {
    ldb_cleanup_t *node, *next;

    ldb_cleanup_run(&iter->cleanup_head);

    for (node = iter->cleanup_head.next; node != NULL; node = next) {
      next = node->next;
      ldb_cleanup_run(node);
      ldb_free(node);
    }
  }

  iter->table->clear(iter->ptr);

  ldb_free(iter->ptr);
}

ldb_iter_t *
ldb_iter_create(void *ptr, const ldb_itertbl_t *table) {
  ldb_iter_t *iter = ldb_malloc(sizeof(ldb_iter_t));
  ldb_iter_init(iter, ptr, table);
  return iter;
}

void
ldb_iter_destroy(ldb_iter_t *iter) {
  ldb_iter_clear(iter);
  ldb_free(iter);
}

void
ldb_iter_register_cleanup(ldb_iter_t *iter,
                          ldb_cleanup_f func,
                          void *arg1,
                          void *arg2) {
  ldb_cleanup_t *node;

  if (ldb_cleanup_empty(&iter->cleanup_head)) {
    node = &iter->cleanup_head;
  } else {
    node = ldb_malloc(sizeof(ldb_cleanup_t));
    node->next = iter->cleanup_head.next;
    iter->cleanup_head.next = node;
  }

  node->func = func;
  node->arg1 = arg1;
  node->arg2 = arg2;
}

/*
 * Empty Iterator
 */

typedef struct ldb_emptyiter_s {
  int status;
} ldb_emptyiter_t;

static void
ldb_emptyiter_clear(ldb_emptyiter_t *iter) {
  (void)iter;
}

static int
ldb_emptyiter_valid(const ldb_emptyiter_t *iter) {
  (void)iter;
  return 0;
}

static void
ldb_emptyiter_seek(ldb_emptyiter_t *iter, const ldb_slice_t *target) {
  (void)iter;
  (void)target;
}

static void
ldb_emptyiter_seek_first(ldb_emptyiter_t *iter) {
  (void)iter;
}

static void
ldb_emptyiter_seek_last(ldb_emptyiter_t *iter) {
  (void)iter;
}

static void
ldb_emptyiter_next(ldb_emptyiter_t *iter) {
  (void)iter;
}

static void
ldb_emptyiter_prev(ldb_emptyiter_t *iter) {
  (void)iter;
}

static ldb_slice_t
ldb_emptyiter_key(const ldb_emptyiter_t *iter) {
  ldb_slice_t ret = {NULL, 0, 0};
  (void)iter;
  assert(0);
  return ret;
}

static ldb_slice_t
ldb_emptyiter_value(const ldb_emptyiter_t *iter) {
  ldb_slice_t ret = {NULL, 0, 0};
  (void)iter;
  assert(0);
  return ret;
}

static int
ldb_emptyiter_status(const ldb_emptyiter_t *iter) {
  return iter->status;
}

LDB_ITERATOR_FUNCTIONS(ldb_emptyiter);

ldb_iter_t *
ldb_emptyiter_create(int status) {
  ldb_emptyiter_t *iter = ldb_malloc(sizeof(ldb_emptyiter_t));

  iter->status = status;

  return ldb_iter_create(iter, &ldb_emptyiter_table);
}
