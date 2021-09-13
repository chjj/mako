/*!
 * outpoint.c - outpoint for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <satoshi/tx.h>
#include <satoshi/util.h>
#include <torsion/hash.h>
#include "impl.h"
#include "internal.h"

/*
 * Outpoint
 */

DEFINE_SERIALIZABLE_OBJECT(btc_outpoint, SCOPE_EXTERN)

void
btc_outpoint_init(btc_outpoint_t *z) {
  memset(z->hash, 0, 32);
  z->index = (uint32_t)-1;
}

void
btc_outpoint_clear(btc_outpoint_t *z) {
  (void)z;
}

void
btc_outpoint_copy(btc_outpoint_t *z, const btc_outpoint_t *x) {
  memcpy(z->hash, x->hash, 32);
  z->index = x->index;
}

uint32_t
btc_outpoint_hash(const btc_outpoint_t *x) {
  uint8_t tmp[36];
  btc_outpoint_write(tmp, x);
  return btc_murmur3_sum(tmp, 36, 0xfba4c795);
}

int
btc_outpoint_equal(const btc_outpoint_t *x, const btc_outpoint_t *y) {
  if (x->index != y->index)
    return 0;

  if (memcmp(x->hash, y->hash, 32) != 0)
    return 0;

  return 1;
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
btc_outpoint_update(hash256_t *ctx, const btc_outpoint_t *x) {
  btc_raw_update(ctx, x->hash, 32);
  btc_uint32_update(ctx, x->index);
}
