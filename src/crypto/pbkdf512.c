/*!
 * pbkdf512.c - sha512 pbkdf2 implementation for mako
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/PBKDF2
 *   https://tools.ietf.org/html/rfc2898
 *   https://tools.ietf.org/html/rfc2898#section-5.2
 *   https://tools.ietf.org/html/rfc6070
 *   https://www.emc.com/collateral/white-papers/h11302-pkcs5v2-1-password-based-cryptography-standard-wp.pdf
 *   http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <mako/crypto/hash.h>
#include <mako/util.h>
#include "../bio.h"
#include "../internal.h"

/*
 * PBKDF512
 */

void
btc_pbkdf512_derive(uint8_t *out,
                    const uint8_t *pass,
                    size_t pass_len,
                    const uint8_t *salt,
                    size_t salt_len,
                    uint32_t iter,
                    size_t len) {
  btc_hmac512_t pmac, smac, hmac;
  size_t i, k, blocks;
  uint8_t block[64];
  uint8_t mac[64];
  uint8_t ctr[4];
  uint32_t j;

  if (len + 63 < len)
    btc_abort(); /* LCOV_EXCL_LINE */

  blocks = (len + 63) / 64;

#if SIZE_MAX > UINT32_MAX
  if (blocks > UINT32_MAX)
    btc_abort(); /* LCOV_EXCL_LINE */
#endif

  if (len == 0)
    return;

  /* Zero for struct assignment. */
  memset(&pmac, 0, sizeof(pmac));
  memset(&smac, 0, sizeof(smac));

  btc_hmac512_init(&pmac, pass, pass_len);

  smac = pmac;

  btc_hmac512_update(&smac, salt, salt_len);

  for (i = 0; i < blocks; i++) {
    btc_write32be(ctr, i + 1);

    hmac = smac;
    btc_hmac512_update(&hmac, ctr, 4);
    btc_hmac512_final(&hmac, block);

    memcpy(mac, block, 64);

    for (j = 1; j < iter; j++) {
      hmac = pmac;
      btc_hmac512_update(&hmac, mac, 64);
      btc_hmac512_final(&hmac, mac);

      for (k = 0; k < 64; k++)
        block[k] ^= mac[k];
    }

    if (len < 64) {
      memcpy(out, block, len);
      break;
    }

    memcpy(out, block, 64);

    out += 64;
    len -= 64;
  }

  btc_memzero(block, sizeof(block));
  btc_memzero(mac, sizeof(mac));
  btc_memzero(&pmac, sizeof(pmac));
  btc_memzero(&smac, sizeof(smac));
  btc_memzero(&hmac, sizeof(hmac));
}
