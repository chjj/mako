/*!
 * heap.c - heap functions for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <limits.h>
#include <stddef.h>
#include <satoshi/heap.h>
#include <satoshi/vector.h>
#include "internal.h"

/*
 * Helpers
 */

static void
heap_swap(btc_vector_t *z, int a, int b) {
  void *x = z->items[a];
  void *y = z->items[b];

  z->items[a] = y;
  z->items[b] = x;
}

static int
heap_less(const btc_vector_t *x, int i, int j, btc_heapcmp_f *cmp) {
  return cmp(x->items[i], x->items[j]) < 0;
}

static void
heap_down(btc_vector_t *z, int i, int n, btc_heapcmp_f *cmp) {
  int l, j, r;

  for (;;) {
    l = 2 * i + 1;

    if (l < 0 || l >= n)
      break;

    j = l;
    r = l + 1;

    if (r < n && !heap_less(z, l, r, cmp))
      j = r;

    if (!heap_less(z, j, i, cmp))
      break;

    heap_swap(z, i, j);
    i = j;
  }
}

static void
heap_up(btc_vector_t *z, int i, btc_heapcmp_f *cmp) {
  int j;

  for (;;) {
    j = (i - 1) / 2;

    if (j < 0 || j == i)
      break;

    if (!heap_less(z, i, j, cmp))
      break;

    heap_swap(z, j, i);
    i = j;
  }
}

/*
 * Heap
 */

void
btc_heap_init(btc_vector_t *z, btc_heapcmp_f *cmp) {
  int n, i;

  CHECK(z->length <= INT_MAX);

  n = z->length;

  for (i = (n / 2) - 1; i >= 0; i--)
    heap_down(z, i, n, cmp);
}

void
btc_heap_insert(btc_vector_t *z, const void *x, btc_heapcmp_f *cmp) {
  CHECK(z->length < INT_MAX);

  btc_vector_push(z, x);
  heap_up(z, z->length - 1, cmp);
}

void *
btc_heap_shift(btc_vector_t *z, btc_heapcmp_f *cmp) {
  int n;

  CHECK(z->length > 0);
  CHECK(z->length <= INT_MAX);

  n = z->length - 1;

  heap_swap(z, 0, n);
  heap_down(z, 0, n, cmp);

  return btc_vector_pop(z);
}

void *
btc_heap_remove(btc_vector_t *z, size_t i, btc_heapcmp_f *cmp) {
  int n;

  CHECK(i < z->length);
  CHECK(z->length <= INT_MAX);

  n = z->length - 1;

  if (n != (int)i) {
    heap_swap(z, i, n);
    heap_down(z, i, n, cmp);
    heap_up(z, i, cmp);
  }

  return btc_vector_pop(z);
}
