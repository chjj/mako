/*!
 * vector.c - shallow vector for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "internal.h"
#include "vector.h"

/*
 * Vector
 */

void
ldb_vector_init(ldb_vector_t *z) {
  z->items = NULL;
  z->length = 0;
  z->alloc = 0;
}

void
ldb_vector_clear(ldb_vector_t *z) {
  if (z->alloc > 0)
    ldb_free(z->items);

  z->items = NULL;
  z->length = 0;
  z->alloc = 0;
}

void
ldb_vector_reset(ldb_vector_t *z) {
  z->length = 0;
}

void
ldb_vector_grow(ldb_vector_t *z, size_t zn) {
  if (zn > z->alloc) {
    z->items = (void **)ldb_realloc(z->items, zn * sizeof(void *));
    z->alloc = zn;
  }
}

void
ldb_vector_push(ldb_vector_t *z, const void *x) {
  if (z->length == z->alloc)
    ldb_vector_grow(z, (z->alloc * 3) / 2 + (z->alloc <= 1));

  z->items[z->length++] = (void *)x;
}

void *
ldb_vector_pop(ldb_vector_t *z) {
  assert(z->length > 0);
  return z->items[--z->length];
}

void *
ldb_vector_top(const ldb_vector_t *z) {
  assert(z->length > 0);
  return (void *)z->items[z->length - 1];
}

void
ldb_vector_resize(ldb_vector_t *z, size_t zn) {
  ldb_vector_grow(z, zn);
  z->length = zn;
}

void
ldb_vector_copy(ldb_vector_t *z, const ldb_vector_t *x) {
  size_t i;

  ldb_vector_resize(z, x->length);

  for (i = 0; i < x->length; i++)
    z->items[i] = x->items[i];
}

void
ldb_vector_swap(ldb_vector_t *x, ldb_vector_t *y) {
  ldb_vector_t t = *x;
  *x = *y;
  *y = t;
}

/**
 * Quicksort
 * https://en.wikipedia.org/wiki/Quicksort#Hoare_partition_scheme
 */

static void
ldb_swap(void **items, int i, int j) {
  void *item = items[i];

  items[i] = items[j];
  items[j] = item;
}

static int
ldb_partition(void **items, int lo, int hi, int (*cmp)(void *, void *)) {
  void *pivot = items[(hi + lo) >> 1];
  int i = lo - 1;
  int j = hi + 1;

  for (;;) {
    do i++; while (cmp(items[i], pivot) < 0);
    do j--; while (cmp(items[j], pivot) > 0);

    if (i >= j)
      return j;

    ldb_swap(items, i, j);
  }
}

static void
ldb_qsort(void **items, int lo, int hi, int (*cmp)(void *, void *)) {
  if (lo >= 0 && hi >= 0 && lo < hi) {
    int p = ldb_partition(items, lo, hi, cmp);

    ldb_qsort(items, lo, p, cmp);
    ldb_qsort(items, p + 1, hi, cmp);
  }
}

void
ldb_vector_sort(ldb_vector_t *z, int (*cmp)(void *, void *)) {
  if (z->length > 1)
    ldb_qsort(z->items, 0, z->length - 1, cmp);
}
