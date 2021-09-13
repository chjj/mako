/*!
 * types.h - crypto types for libsatoshi
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef BTC_CRYPTO_TYPES_H
#define BTC_CRYPTO_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

typedef struct btc_chacha20_s {
  uint32_t state[16];
  uint32_t stream[16];
  size_t pos;
} btc_chacha20_t;

typedef struct btc_ripemd160_s {
  uint32_t state[5];
  uint8_t block[64];
  uint64_t size;
} btc_ripemd160_t;

typedef struct btc_sha1_s {
  uint32_t state[5];
  uint8_t block[64];
  uint64_t size;
} btc_sha1_t;

typedef struct btc_sha256_s {
  uint32_t state[8];
  uint8_t block[64];
  uint64_t size;
} btc_sha256_t;

typedef btc_sha256_t btc_hash160_t;
typedef btc_sha256_t btc_hash256_t;

typedef struct btc_hmac_s {
  btc_sha256_t inner;
  btc_sha256_t outer;
} btc_hmac_t;

typedef struct btc_drbg_s {
  btc_hmac_t kmac;
  uint8_t K[32];
  uint8_t V[32];
} btc_drbg_t;

#endif /* BTC_CRYPTO_TYPES_H */
