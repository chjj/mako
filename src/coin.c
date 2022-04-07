/*!
 * coin.c - coin for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <mako/coins.h>
#include <mako/tx.h>
#include "impl.h"
#include "internal.h"

/*
 * Coin
 */

DEFINE_SERIALIZABLE_REFOBJ(btc_coin, SCOPE_EXTERN)

void
btc_coin_init(btc_coin_t *z) {
  z->version = 1;
  z->height = -1;
  z->coinbase = 0;
  z->spent = 0;
  z->safe = 0;
  z->watch = 0;
  btc_output_init(&z->output);
  z->_refs = 0;
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
  z->safe = x->safe;
  z->watch = x->watch;
  btc_output_copy(&z->output, &x->output);
}

size_t
btc_coin_size(const btc_coin_t *x) {
  uint32_t flags = (uint32_t)x->height * 2 + x->coinbase;
  size_t size = 0;

  size += btc_varint_size(x->version);
  size += btc_varint_size(flags);
  size += btc_output_deflate(&x->output);

  return size;
}

uint8_t *
btc_coin_write(uint8_t *zp, const btc_coin_t *x) {
  uint32_t flags = (uint32_t)x->height * 2 + x->coinbase;

  zp = btc_varint_write(zp, x->version);
  zp = btc_varint_write(zp, flags);
  zp = btc_output_compress(zp, &x->output);

  return zp;
}

int
btc_coin_read(btc_coin_t *z, const uint8_t **xp, size_t *xn) {
  uint64_t version, flags;

  if (!btc_varint_read(&version, xp, xn))
    return 0;

  if (version > UINT32_MAX)
    return 0;

  if (!btc_varint_read(&flags, xp, xn))
    return 0;

  if (flags > UINT32_MAX)
    return 0;

  z->version = version;
  z->height = flags >> 1;
  z->coinbase = flags & 1;
  z->spent = 0;
  z->safe = 0;
  z->watch = 0;

  if (z->height == INT32_MAX)
    z->height = -1;

  if (!btc_output_decompress(&z->output, xp, xn))
    return 0;

  return 1;
}
