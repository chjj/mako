/*!
 * buffer.c - buffer for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <mako/buffer.h>
#include <mako/crypto/hash.h>
#include "impl.h"
#include "internal.h"

/*
 * Buffer
 */

DEFINE_SERIALIZABLE_REFOBJ(btc_buffer, SCOPE_EXTERN)

void
btc_buffer_init(btc_buffer_t *z) {
  z->data = NULL;
  z->alloc = 0;
  z->length = 0;
  z->_refs = 0;
}

void
btc_buffer_clear(btc_buffer_t *z) {
  if (z->alloc > 0)
    btc_free(z->data);

  z->data = NULL;
  z->alloc = 0;
  z->length = 0;
}

void
btc_buffer_reset(btc_buffer_t *z) {
  z->length = 0;
}

uint8_t *
btc_buffer_grow(btc_buffer_t *z, size_t zn) {
  if (zn > z->alloc) {
    z->data = (uint8_t *)btc_realloc(z->data, zn);
    z->alloc = zn;
  }

  return z->data;
}

uint8_t *
btc_buffer_resize(btc_buffer_t *z, size_t zn) {
  btc_buffer_grow(z, zn);
  z->length = zn;
  return z->data;
}

void
btc_buffer_set(btc_buffer_t *z, const uint8_t *xp, size_t xn) {
  btc_buffer_grow(z, xn);

  if (xn > 0)
    memcpy(z->data, xp, xn);

  z->length = xn;
}

void
btc_buffer_copy(btc_buffer_t *z, const btc_buffer_t *x) {
  btc_buffer_set(z, x->data, x->length);
}

void
btc_buffer_roset(btc_buffer_t *z, const uint8_t *xp, size_t xn) {
  z->data = (uint8_t *)xp;
  z->length = xn;
  z->alloc = 0;
}

void
btc_buffer_rocopy(btc_buffer_t *z, const btc_buffer_t *x) {
  btc_buffer_roset(z, x->data, x->length);
}

btc_buffer_t *
btc_buffer_roclone(const btc_buffer_t *x) {
  btc_buffer_t *z = btc_buffer_create();
  btc_buffer_rocopy(z, x);
  return z;
}

int
btc_buffer_equal(const btc_buffer_t *x, const btc_buffer_t *y) {
  if (x->length != y->length)
    return 0;

  if (x->length > 0) {
    if (memcmp(x->data, y->data, x->length) != 0)
      return 0;
  }

  return 1;
}

size_t
btc_buffer_size(const btc_buffer_t *x) {
  return btc_size_size(x->length) + x->length;
}

uint8_t *
btc_buffer_write(uint8_t *zp, const btc_buffer_t *x) {
  zp = btc_size_write(zp, x->length);
  zp = btc_raw_write(zp, x->data, x->length);
  return zp;
}

int
btc_buffer_read(btc_buffer_t *z, const uint8_t **xp, size_t *xn) {
  const uint8_t *zp;
  size_t zn;

  if (!btc_size_read(&zn, xp, xn))
    return 0;

  if (!btc_zraw_read(&zp, zn, xp, xn))
    return 0;

  btc_buffer_set(z, zp, zn);

  return 1;
}

void
btc_buffer_update(btc_hash256_t *ctx, const btc_buffer_t *x) {
  btc_size_update(ctx, x->length);
  btc_raw_update(ctx, x->data, x->length);
}
