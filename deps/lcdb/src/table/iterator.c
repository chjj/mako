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

#define LDB_ITERATOR_C

#include <assert.h>
#include <stddef.h>

#include "../util/comparator.h"
#include "../util/internal.h"
#include "../util/types.h"

#include "iterator.h"

/*
 * Iterator
 */

static void
ldb_iter_init(ldb_iter_t *iter,
              void *ptr,
              const ldb_itertbl_t *table,
              const ldb_comparator_t *cmp) {
  iter->ptr = ptr;
  iter->cleanup_head.func = NULL;
  iter->cleanup_head.next = NULL;
  iter->table = table;
  iter->cmp = cmp;
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
ldb_iter_create(void *ptr,
                const ldb_itertbl_t *table,
                const ldb_comparator_t *cmp) {
  ldb_iter_t *iter = ldb_malloc(sizeof(ldb_iter_t));
  ldb_iter_init(iter, ptr, table, cmp);
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

int
ldb_iter_valid(const ldb_iter_t *iter) {
  return iter->table->valid(iter->ptr);
}

void
ldb_iter_first(ldb_iter_t *iter) {
  iter->table->first(iter->ptr);
}

void
ldb_iter_last(ldb_iter_t *iter) {
  iter->table->last(iter->ptr);
}

void
ldb_iter_seek(ldb_iter_t *iter, const ldb_slice_t *target) {
  iter->table->seek(iter->ptr, target);
}

void
ldb_iter_next(ldb_iter_t *iter) {
  iter->table->next(iter->ptr);
}

void
ldb_iter_prev(ldb_iter_t *iter) {
  iter->table->prev(iter->ptr);
}

ldb_slice_t
ldb_iter_key(const ldb_iter_t *iter) {
  return iter->table->key(iter->ptr);
}

ldb_slice_t
ldb_iter_value(const ldb_iter_t *iter) {
  return iter->table->value(iter->ptr);
}

int
ldb_iter_status(const ldb_iter_t *iter) {
  return iter->table->status(iter->ptr);
}

int
ldb_iter_compare(const ldb_iter_t *iter, const ldb_slice_t *key) {
  ldb_slice_t x = iter->table->key(iter->ptr);
  return ldb_compare(iter->cmp, &x, key);
}

void
ldb_iter_seek_ge(ldb_iter_t *iter, const ldb_slice_t *target) {
  iter->table->seek(iter->ptr, target);
}

void
ldb_iter_seek_gt(ldb_iter_t *iter, const ldb_slice_t *target) {
  iter->table->seek(iter->ptr, target);

  if (iter->table->valid(iter->ptr)) {
    if (ldb_iter_compare(iter, target) == 0)
      iter->table->next(iter->ptr);
  }
}

void
ldb_iter_seek_le(ldb_iter_t *iter, const ldb_slice_t *target) {
  iter->table->seek(iter->ptr, target);

  if (iter->table->valid(iter->ptr)) {
    if (ldb_iter_compare(iter, target) > 0)
      iter->table->prev(iter->ptr);
  } else {
    iter->table->last(iter->ptr);
  }
}

void
ldb_iter_seek_lt(ldb_iter_t *iter, const ldb_slice_t *target) {
  iter->table->seek(iter->ptr, target);

  if (iter->table->valid(iter->ptr))
    iter->table->prev(iter->ptr);
  else
    iter->table->last(iter->ptr);
}

/*
 * Empty Comparator
 */

static int
empty_compare(const ldb_comparator_t *comparator,
              const ldb_slice_t *x,
              const ldb_slice_t *y) {
  (void)comparator;
  (void)x;
  (void)y;
  assert(0);
  return -1;
}

static const ldb_comparator_t empty_comparator = {
  /* .name = */ "leveldb.EmptyComparator",
  /* .compare = */ empty_compare,
  /* .shortest_separator = */ NULL,
  /* .short_successor = */ NULL,
  /* .user_comparator = */ NULL,
  /* .state = */ NULL
};

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
ldb_emptyiter_first(ldb_emptyiter_t *iter) {
  (void)iter;
}

static void
ldb_emptyiter_last(ldb_emptyiter_t *iter) {
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

  return ldb_iter_create(iter, &ldb_emptyiter_table, &empty_comparator);
}
