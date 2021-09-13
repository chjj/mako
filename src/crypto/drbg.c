/*!
 * drbg.c - hmac-drbg implementation for libsatoshi
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/HMAC
 *   https://tools.ietf.org/html/rfc2104
 *   https://tools.ietf.org/html/rfc6979
 *   https://csrc.nist.gov/publications/detail/sp/800-90a/archive/2012-01-23
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <satoshi/crypto/drbg.h>
#include <satoshi/crypto/hash.h>
#include <satoshi/util.h>

/*
 * HMAC
 */

static void
hmac_init(btc_hmac_t *hmac, const uint8_t *key, size_t len) {
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

static void
hmac_update(btc_hmac_t *hmac, const void *data, size_t len) {
  btc_sha256_update(&hmac->inner, data, len);
}

static void
hmac_final(btc_hmac_t *hmac, uint8_t *out) {
  btc_sha256_final(&hmac->inner, out);
  btc_sha256_update(&hmac->outer, out, 32);
  btc_sha256_final(&hmac->outer, out);
}

/*
 * HMAC-DRBG
 */

static void
btc_drbg_update(btc_drbg_t *drbg, const uint8_t *seed, size_t seed_len) {
  static const uint8_t zero[1] = {0x00};
  static const uint8_t one[1] = {0x01};

  hmac_init(&drbg->kmac, drbg->K, 32);
  hmac_update(&drbg->kmac, drbg->V, 32);
  hmac_update(&drbg->kmac, zero, 1);
  hmac_update(&drbg->kmac, seed, seed_len);
  hmac_final(&drbg->kmac, drbg->K);

  hmac_init(&drbg->kmac, drbg->K, 32);
  hmac_update(&drbg->kmac, drbg->V, 32);
  hmac_final(&drbg->kmac, drbg->V);

  if (seed_len > 0) {
    hmac_init(&drbg->kmac, drbg->K, 32);
    hmac_update(&drbg->kmac, drbg->V, 32);
    hmac_update(&drbg->kmac, one, 1);
    hmac_update(&drbg->kmac, seed, seed_len);
    hmac_final(&drbg->kmac, drbg->K);

    hmac_init(&drbg->kmac, drbg->K, 32);
    hmac_update(&drbg->kmac, drbg->V, 32);
    hmac_final(&drbg->kmac, drbg->V);
  }

  hmac_init(&drbg->kmac, drbg->K, 32);
}

void
btc_drbg_init(btc_drbg_t *drbg, const uint8_t *seed, size_t seed_len) {
  memset(drbg->K, 0x00, 32);
  memset(drbg->V, 0x01, 32);

  /* Zero for struct assignment. */
  memset(&drbg->kmac, 0, sizeof(drbg->kmac));

  btc_drbg_update(drbg, seed, seed_len);
}

void
btc_drbg_reseed(btc_drbg_t *drbg, const uint8_t *seed, size_t seed_len) {
  btc_drbg_update(drbg, seed, seed_len);
}

void
btc_drbg_generate(btc_drbg_t *drbg, void *out, size_t len) {
  uint8_t *raw = (uint8_t *)out;
  size_t size = 32;
  btc_hmac_t kmac;

  while (len > 0) {
    kmac = drbg->kmac;
    hmac_update(&kmac, drbg->V, size);
    hmac_final(&kmac, drbg->V);

    if (size > len)
      size = len;

    memcpy(raw, drbg->V, size);

    raw += size;
    len -= size;
  }

  btc_drbg_update(drbg, NULL, 0);
}

void
btc_drbg_rng(void *out, size_t size, void *arg) {
  btc_drbg_generate((btc_drbg_t *)arg, out, size);
}
