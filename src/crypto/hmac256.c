/*!
 * hmac256.c - sha256 hmac implementation for mako
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/HMAC
 *   https://tools.ietf.org/html/rfc2104
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <mako/crypto/hash.h>
#include <mako/util.h>

/*
 * HMAC256
 */

void
btc_hmac256_init(btc_hmac256_t *hmac, const uint8_t *key, size_t len) {
  uint8_t tmp[32];
  uint8_t pad[64];
  size_t i;

  if (len > 64) {
    btc_sha256_init(&hmac->inner);
    btc_sha256_update(&hmac->inner, key, len);
    btc_sha256_final(&hmac->inner, tmp);
    key = tmp;
    len = 32;
  }

  for (i = 0; i < len; i++)
    pad[i] = key[i] ^ 0x36;

  for (i = len; i < 64; i++)
    pad[i] = 0x36;

  btc_sha256_init(&hmac->inner);
  btc_sha256_update(&hmac->inner, pad, 64);

  for (i = 0; i < len; i++)
    pad[i] = key[i] ^ 0x5c;

  for (i = len; i < 64; i++)
    pad[i] = 0x5c;

  btc_sha256_init(&hmac->outer);
  btc_sha256_update(&hmac->outer, pad, 64);

  btc_memzero(tmp, 32);
  btc_memzero(pad, 64);
}

void
btc_hmac256_update(btc_hmac256_t *hmac, const void *data, size_t len) {
  btc_sha256_update(&hmac->inner, data, len);
}

void
btc_hmac256_final(btc_hmac256_t *hmac, uint8_t *out) {
  btc_sha256_final(&hmac->inner, out);
  btc_sha256_update(&hmac->outer, out, 32);
  btc_sha256_final(&hmac->outer, out);
}
