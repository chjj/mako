/*!
 * hmac512.c - sha512 hmac implementation for mako
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
 * HMAC512
 */

void
btc_hmac512_init(btc_hmac512_t *hmac, const uint8_t *key, size_t len) {
  uint8_t tmp[64];
  uint8_t pad[128];
  size_t i;

  if (len > 128) {
    btc_sha512_init(&hmac->inner);
    btc_sha512_update(&hmac->inner, key, len);
    btc_sha512_final(&hmac->inner, tmp);
    key = tmp;
    len = 64;
  }

  for (i = 0; i < len; i++)
    pad[i] = key[i] ^ 0x36;

  for (i = len; i < 128; i++)
    pad[i] = 0x36;

  btc_sha512_init(&hmac->inner);
  btc_sha512_update(&hmac->inner, pad, 128);

  for (i = 0; i < len; i++)
    pad[i] = key[i] ^ 0x5c;

  for (i = len; i < 128; i++)
    pad[i] = 0x5c;

  btc_sha512_init(&hmac->outer);
  btc_sha512_update(&hmac->outer, pad, 128);

  btc_memzero(tmp, 64);
  btc_memzero(pad, 128);
}

void
btc_hmac512_update(btc_hmac512_t *hmac, const void *data, size_t len) {
  btc_sha512_update(&hmac->inner, data, len);
}

void
btc_hmac512_final(btc_hmac512_t *hmac, uint8_t *out) {
  btc_sha512_final(&hmac->inner, out);
  btc_sha512_update(&hmac->outer, out, 64);
  btc_sha512_final(&hmac->outer, out);
}
