/*!
 * drbg.c - hmac-drbg implementation for mako
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
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
#include <mako/crypto/drbg.h>
#include <mako/crypto/hash.h>
#include <mako/util.h>

/*
 * HMAC-DRBG
 */

static void
btc_drbg_update(btc_drbg_t *drbg, const uint8_t *seed, size_t seed_len) {
  static const uint8_t zero[1] = {0x00};
  static const uint8_t one[1] = {0x01};

  btc_hmac256_init(&drbg->kmac, drbg->K, 32);
  btc_hmac256_update(&drbg->kmac, drbg->V, 32);
  btc_hmac256_update(&drbg->kmac, zero, 1);
  btc_hmac256_update(&drbg->kmac, seed, seed_len);
  btc_hmac256_final(&drbg->kmac, drbg->K);

  btc_hmac256_init(&drbg->kmac, drbg->K, 32);
  btc_hmac256_update(&drbg->kmac, drbg->V, 32);
  btc_hmac256_final(&drbg->kmac, drbg->V);

  if (seed_len > 0) {
    btc_hmac256_init(&drbg->kmac, drbg->K, 32);
    btc_hmac256_update(&drbg->kmac, drbg->V, 32);
    btc_hmac256_update(&drbg->kmac, one, 1);
    btc_hmac256_update(&drbg->kmac, seed, seed_len);
    btc_hmac256_final(&drbg->kmac, drbg->K);

    btc_hmac256_init(&drbg->kmac, drbg->K, 32);
    btc_hmac256_update(&drbg->kmac, drbg->V, 32);
    btc_hmac256_final(&drbg->kmac, drbg->V);
  }

  btc_hmac256_init(&drbg->kmac, drbg->K, 32);
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
  btc_hmac256_t kmac;

  while (len > 0) {
    kmac = drbg->kmac;
    btc_hmac256_update(&kmac, drbg->V, 32);
    btc_hmac256_final(&kmac, drbg->V);

    if (len < 32) {
      memcpy(raw, drbg->V, len);
      break;
    }

    memcpy(raw, drbg->V, 32);

    raw += 32;
    len -= 32;
  }

  btc_drbg_update(drbg, NULL, 0);
}

void
btc_drbg_rng(void *out, size_t size, void *arg) {
  btc_drbg_generate((btc_drbg_t *)arg, out, size);
}
