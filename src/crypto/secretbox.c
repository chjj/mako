/*!
 * secretbox.c - secretbox for mako
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 *
 * Resources:
 *   https://nacl.cr.yp.to/secretbox.html
 */

#include <stddef.h>
#include <stdint.h>
#include <mako/crypto/ies.h>
#include <mako/crypto/mac.h>
#include <mako/crypto/stream.h>
#include <mako/util.h>

/*
 * Constants
 */

static const uint8_t zero32[32] = {0};

/*
 * Secret Box
 */

void
btc_secretbox_seal(uint8_t *sealed,
                   const uint8_t *msg,
                   size_t msg_len,
                   const uint8_t *key,
                   const uint8_t *nonce) {
  uint8_t *tag = sealed;
  uint8_t *ct = sealed + 16;
  uint8_t polykey[32];
  btc_poly1305_t poly;
  btc_salsa20_t salsa;

  btc_salsa20_init(&salsa, key, 32, nonce, 24, 0);
  btc_salsa20_crypt(&salsa, polykey, zero32, 32);
  btc_salsa20_crypt(&salsa, ct, msg, msg_len);

  btc_poly1305_init(&poly, polykey);
  btc_poly1305_update(&poly, ct, msg_len);
  btc_poly1305_final(&poly, tag);

  btc_memzero(&salsa, sizeof(salsa));
}

int
btc_secretbox_open(uint8_t *msg,
                   const uint8_t *sealed,
                   size_t sealed_len,
                   const uint8_t *key,
                   const uint8_t *nonce) {
  const uint8_t *tag, *ct;
  btc_poly1305_t poly;
  btc_salsa20_t salsa;
  uint8_t polykey[32];
  uint8_t mac[16];
  size_t ct_len;
  int ret;

  if (sealed_len < 16)
    return 0;

  tag = sealed;
  ct = sealed + 16;
  ct_len = sealed_len - 16;

  btc_salsa20_init(&salsa, key, 32, nonce, 24, 0);
  btc_salsa20_crypt(&salsa, polykey, zero32, 32);

  btc_poly1305_init(&poly, polykey);
  btc_poly1305_update(&poly, ct, ct_len);
  btc_poly1305_final(&poly, mac);

  ret = btc_memequal(mac, tag, 16);

  btc_salsa20_crypt(&salsa, msg, ct, ct_len);

  btc_memzero(&salsa, sizeof(salsa));

  return ret;
}

void
btc_secretbox_derive(uint8_t *key, const uint8_t *secret) {
  btc_salsa20_derive(key, secret, 32, zero32);
}
