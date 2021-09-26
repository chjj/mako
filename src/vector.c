/*!
 * vector.c - shallow vector for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stdlib.h>
#include <string.h>
#include <satoshi/vector.h>
#include "impl.h"
#include "internal.h"

/*
 * Vector
 */

DEFINE_OBJECT(btc_vector, SCOPE_EXTERN)

void
btc_vector_init(btc_vector_t *z) {
  z->items = NULL;
  z->alloc = 0;
  z->length = 0;
}

void
btc_vector_clear(btc_vector_t *z) {
  if (z->alloc > 0)
    free(z->items);

  z->items = NULL;
  z->alloc = 0;
  z->length = 0;
}

void
btc_vector_reset(btc_vector_t *z) {
  z->length = 0;
}

void
btc_vector_grow(btc_vector_t *z, size_t zn) {
  if (zn > z->alloc) {
    void **zp = (void **)realloc(z->items, zn * sizeof(void *));

    CHECK(zp != NULL);

    z->items = zp;
    z->alloc = zn;
  }
}

void
btc_vector_push(btc_vector_t *z, const void *x) {
  if (z->length == z->alloc)
    btc_vector_grow(z, (z->alloc * 3) / 2 + (z->alloc <= 1));

  z->items[z->length++] = (void *)x;
}

void *
btc_vector_pop(btc_vector_t *z) {
  CHECK(z->length > 0);
  return z->items[--z->length];
}

void *
btc_vector_top(const btc_vector_t *z) {
  CHECK(z->length > 0);
  return (void *)z->items[z->length - 1];
}

void
btc_vector_resize(btc_vector_t *z, size_t zn) {
  if (z->length < zn)
    btc_vector_grow(z, zn);

  z->length = zn;
}

void
btc_vector_copy(btc_vector_t *x, const btc_vector_t *y) {
  size_t i;

  btc_vector_resize(x, y->length);

  for (i = 0; i < y->length; i++)
    x->items[i] = y->items[i];
}
