/*!
 * coin.c - coin for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <satoshi/coins.h>
#include "impl.h"
#include "internal.h"

/*
 * Coin
 */

DEFINE_SERIALIZABLE_OBJECT(btc_coin, SCOPE_EXTERN)

void
btc_coin_init(btc_coin_t *z) {
  z->version = 1;
  z->height = (uint32_t)-1;
  z->coinbase = 0;
  z->spent = 0;
  btc_output_init(&z->output);
}

void
btc_coin_clear(btc_coin_t *z) {
  btc_output_clear(&z->output);
}

void
btc_coin_copy(btc_coin_t *z, const btc_coin_t *x) {
  z->version = x->version;
  z->height = x->height;
  z->coinbase = x->coinbase;
  z->spent = x->spent;
  btc_output_copy(&z->output, &x->output);
}

size_t
btc_coin_size(const btc_coin_t *x) {
  size_t size = 0;

  size += btc_varint_size(x->version);
  size += 4;
  size += 1;
  size += btc_output_size(&x->output);

  return size;
}

uint8_t *
btc_coin_write(uint8_t *zp, const btc_coin_t *x) {
  zp = btc_varint_write(zp, x->version);
  zp = btc_uint32_write(zp, x->height);
  zp = btc_uint8_write(zp, x->coinbase);
  zp = btc_output_write(zp, &x->output);
  return zp;
}

int
btc_coin_read(btc_coin_t *z, const uint8_t **xp, size_t *xn) {
  uint64_t version;
  uint8_t flags;

  if (!btc_varint_read(&version, xp, xn))
    return 0;

  z->version = (uint32_t)version;

  if (!btc_uint32_read(&z->height, xp, xn))
    return 0;

  if (!btc_uint8_read(&flags, xp, xn))
    return 0;

  z->coinbase = flags & 1;
  z->spent = 0;

  if (!btc_output_read(&z->output, xp, xn))
    return 0;

  return 1;
}
