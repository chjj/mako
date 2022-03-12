/*!
 * array.c - integer vector for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 */

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "array.h"
#include "internal.h"

/*
 * Integer Vector
 */

void
ldb_array_init(ldb_array_t *z) {
  z->items = NULL;
  z->length = 0;
  z->alloc = 0;
}

void
ldb_array_clear(ldb_array_t *z) {
  if (z->alloc > 0)
    ldb_free(z->items);

  z->items = NULL;
  z->length = 0;
  z->alloc = 0;
}

void
ldb_array_reset(ldb_array_t *z) {
  z->length = 0;
}

void
ldb_array_grow(ldb_array_t *z, size_t zn) {
  if (zn > z->alloc) {
    z->items = (int64_t *)ldb_realloc(z->items, zn * sizeof(int64_t));
    z->alloc = zn;
  }
}

void
ldb_array_push(ldb_array_t *z, int64_t x) {
  if (z->length == z->alloc)
    ldb_array_grow(z, (z->alloc * 3) / 2 + (z->alloc <= 1));

  z->items[z->length++] = x;
}

int64_t
ldb_array_pop(ldb_array_t *z) {
  assert(z->length > 0);
  return z->items[--z->length];
}

int64_t
ldb_array_top(const ldb_array_t *z) {
  assert(z->length > 0);
  return z->items[z->length - 1];
}

void
ldb_array_resize(ldb_array_t *z, size_t zn) {
  ldb_array_grow(z, zn);
  z->length = zn;
}

void
ldb_array_copy(ldb_array_t *z, const ldb_array_t *x) {
  size_t i;

  ldb_array_resize(z, x->length);

  for (i = 0; i < x->length; i++)
    z->items[i] = x->items[i];
}

void
ldb_array_swap(ldb_array_t *x, ldb_array_t *y) {
  ldb_array_t t = *x;
  *x = *y;
  *y = t;
}

/**
 * Quicksort (faster than libc's qsort -- no memcpy necessary)
 * https://en.wikipedia.org/wiki/Quicksort#Hoare_partition_scheme
 */

static void
ldb_swap(int64_t *items, int i, int j) {
  int64_t item = items[i];

  items[i] = items[j];
  items[j] = item;
}

static int
ldb_partition(int64_t *items, int lo, int hi, int (*cmp)(int64_t, int64_t)) {
  int64_t pivot = items[(hi + lo) >> 1];
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
ldb_qsort(int64_t *items, int lo, int hi, int (*cmp)(int64_t, int64_t)) {
  if (lo >= 0 && hi >= 0 && lo < hi) {
    int p = ldb_partition(items, lo, hi, cmp);

    ldb_qsort(items, lo, p, cmp);
    ldb_qsort(items, p + 1, hi, cmp);
  }
}

void
ldb_array_sort(ldb_array_t *z, int (*cmp)(int64_t, int64_t)) {
  if (z->length > 1)
    ldb_qsort(z->items, 0, z->length - 1, cmp);
}
