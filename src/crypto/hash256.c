/*!
 * hash256.c - hash256 function for mako
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 *
 * Resources:
 *   https://github.com/bitcoin/bitcoin/blob/master/src/hash.h
 */

#include <stddef.h>
#include <stdint.h>
#include <mako/crypto/hash.h>
#include "../bio.h"

/*
 * Hash256
 */

void
btc_hash256_final(btc_hash256_t *ctx, uint8_t *out) {
  btc_sha256_final(ctx, out);
  btc_sha256_init(ctx);
  btc_sha256_update(ctx, out, 32);
  btc_sha256_final(ctx, out);
}

void
btc_hash256(uint8_t *out, const void *data, size_t size) {
  btc_hash256_t ctx;
  btc_hash256_init(&ctx);
  btc_hash256_update(&ctx, data, size);
  btc_hash256_final(&ctx, out);
}

void
btc_hash256_root(uint8_t *out, const void *left, const void *right) {
  btc_hash256_t ctx;
  btc_hash256_init(&ctx);
  btc_hash256_update(&ctx, left, 32);
  btc_hash256_update(&ctx, right, 32);
  btc_hash256_final(&ctx, out);
}

uint32_t
btc_checksum(const void *data, size_t size) {
  uint8_t hash[32];
  btc_hash256(hash, data, size);
  return btc_read32le(hash);
}
