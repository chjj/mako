/*!
 * outpoint.c - outpoint for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <mako/crypto/hash.h>
#include <mako/tx.h>
#include <mako/util.h>
#include "impl.h"
#include "internal.h"

/*
 * Outpoint
 */

DEFINE_SERIALIZABLE_OBJECT(btc_outpoint, SCOPE_EXTERN)

void
btc_outpoint_init(btc_outpoint_t *z) {
  btc_hash_init(z->hash);
  z->index = (uint32_t)-1;
}

void
btc_outpoint_clear(btc_outpoint_t *z) {
  (void)z;
}

void
btc_outpoint_copy(btc_outpoint_t *z, const btc_outpoint_t *x) {
  btc_hash_copy(z->hash, x->hash);
  z->index = x->index;
}

void
btc_outpoint_set(btc_outpoint_t *z, const uint8_t *hash, uint32_t index) {
  btc_hash_copy(z->hash, hash);
  z->index = index;
}

uint32_t
btc_outpoint_hash(const btc_outpoint_t *x) {
  return btc_murmur3_sum(x->hash, 32, x->index ^ 0xfba4c795);
}

int
btc_outpoint_equal(const btc_outpoint_t *x, const btc_outpoint_t *y) {
  if (x->index != y->index)
    return 0;

  if (!btc_hash_equal(x->hash, y->hash))
    return 0;

  return 1;
}

int
btc_outpoint_compare(const btc_outpoint_t *x, const btc_outpoint_t *y) {
  int cmp = btc_hash_compare(x->hash, y->hash);

  if (cmp != 0)
    return cmp;

  if (x->index < y->index)
    return -1;

  if (x->index > y->index)
    return 1;

  return 0;
}

int
btc_outpoint_is_null(const btc_outpoint_t *x) {
  static const btc_outpoint_t zero = {{0}, 0xffffffff};
  return btc_outpoint_equal(x, &zero);
}

size_t
btc_outpoint_size(const btc_outpoint_t *x) {
  (void)x;
  return 32 + 4;
}

uint8_t *
btc_outpoint_write(uint8_t *zp, const btc_outpoint_t *x) {
  zp = btc_raw_write(zp, x->hash, 32);
  zp = btc_uint32_write(zp, x->index);
  return zp;
}

int
btc_outpoint_read(btc_outpoint_t *z, const uint8_t **xp, size_t *xn) {
  if (!btc_raw_read(z->hash, 32, xp, xn))
    return 0;

  if (!btc_uint32_read(&z->index, xp, xn))
    return 0;

  return 1;
}

void
btc_outpoint_update(btc_hash256_t *ctx, const btc_outpoint_t *x) {
  btc_raw_update(ctx, x->hash, 32);
  btc_uint32_update(ctx, x->index);
}
