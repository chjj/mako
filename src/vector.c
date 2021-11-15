/*!
 * vector.c - shallow vector for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdlib.h>
#include <string.h>
#include <mako/vector.h>
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
    btc_free(z->items);

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
    z->items = (void **)btc_realloc(z->items, zn * sizeof(void *));
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
  btc_vector_grow(z, zn);
  z->length = zn;
}

void
btc_vector_copy(btc_vector_t *z, const btc_vector_t *x) {
  size_t i;

  btc_vector_resize(z, x->length);

  for (i = 0; i < x->length; i++)
    z->items[i] = x->items[i];
}
