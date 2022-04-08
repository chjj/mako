/*!
 * stream.h - stream ciphers for mako
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifndef BTC_STREAM_H
#define BTC_STREAM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "../common.h"
#include "types.h"

/*
 * ChaCha20
 */

BTC_EXTERN void
btc_chacha20_init(btc_chacha20_t *ctx,
                  const uint8_t *key,
                  size_t key_len,
                  const uint8_t *nonce,
                  size_t nonce_len,
                  uint64_t counter);

BTC_EXTERN void
btc_chacha20_crypt(btc_chacha20_t *ctx,
                   uint8_t *dst,
                   const uint8_t *src,
                   size_t len);

/*
 * Salsa20
 */

BTC_EXTERN void
btc_salsa20_init(btc_salsa20_t *ctx,
                 const uint8_t *key,
                 size_t key_len,
                 const uint8_t *nonce,
                 size_t nonce_len,
                 uint64_t counter);

BTC_EXTERN void
btc_salsa20_crypt(btc_salsa20_t *ctx,
                  uint8_t *dst,
                  const uint8_t *src,
                  size_t len);

BTC_EXTERN void
btc_salsa20_derive(uint8_t *out,
                   const uint8_t *key,
                   size_t key_len,
                   const uint8_t *nonce16);

#ifdef __cplusplus
}
#endif

#endif /* BTC_STREAM_H */
