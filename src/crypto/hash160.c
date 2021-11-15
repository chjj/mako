/*!
 * hash160.c - hash160 function for mako
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 *
 * Resources:
 *   https://github.com/bitcoin/bitcoin/blob/master/src/hash.h
 */

#include <stddef.h>
#include <stdint.h>
#include <mako/crypto/hash.h>
#include <mako/util.h>

/*
 * Hash160
 */

void
btc_hash160_final(btc_hash160_t *ctx, uint8_t *out) {
  btc_ripemd160_t rmd;
  uint8_t tmp[32];

  btc_sha256_final(ctx, tmp);

  btc_ripemd160_init(&rmd);
  btc_ripemd160_update(&rmd, tmp, 32);
  btc_ripemd160_final(&rmd, out);

  btc_memzero(tmp, sizeof(tmp));
}

void
btc_hash160(uint8_t *out, const void *data, size_t size) {
  btc_hash160_t ctx;
  btc_hash160_init(&ctx);
  btc_hash160_update(&ctx, data, size);
  btc_hash160_final(&ctx, out);
}
