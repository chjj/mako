/*!
 * hash.h - hash functions for mako
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifndef BTC_HASH_H
#define BTC_HASH_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "../common.h"
#include "types.h"

/*
 * Hash160
 */

#define btc_hash160_init btc_sha256_init
#define btc_hash160_update btc_sha256_update

BTC_EXTERN void
btc_hash160_final(btc_hash160_t *ctx, uint8_t *out);

BTC_EXTERN void
btc_hash160(uint8_t *out, const void *data, size_t size);

/*
 * Hash256
 */

#define btc_hash256_init btc_sha256_init
#define btc_hash256_update btc_sha256_update

BTC_EXTERN void
btc_hash256_final(btc_hash256_t *ctx, uint8_t *out);

BTC_EXTERN void
btc_hash256(uint8_t *out, const void *data, size_t size);

BTC_EXTERN void
btc_hash256_root(uint8_t *out, const void *left, const void *right);

BTC_EXTERN uint32_t
btc_checksum(const void *data, size_t size);

/*
 * RIPEMD160
 */

BTC_EXTERN void
btc_ripemd160_init(btc_ripemd160_t *ctx);

BTC_EXTERN void
btc_ripemd160_update(btc_ripemd160_t *ctx, const void *data, size_t len);

BTC_EXTERN void
btc_ripemd160_final(btc_ripemd160_t *ctx, uint8_t *out);

BTC_EXTERN void
btc_ripemd160(uint8_t *out, const void *data, size_t size);

/*
 * SHA1
 */

BTC_EXTERN void
btc_sha1_init(btc_sha1_t *ctx);

BTC_EXTERN void
btc_sha1_update(btc_sha1_t *ctx, const void *data, size_t len);

BTC_EXTERN void
btc_sha1_final(btc_sha1_t *ctx, uint8_t *out);

BTC_EXTERN void
btc_sha1(uint8_t *out, const void *data, size_t size);

/*
 * SHA256
 */

BTC_EXTERN void
btc_sha256_init(btc_sha256_t *ctx);

BTC_EXTERN void
btc_sha256_update(btc_sha256_t *ctx, const void *data, size_t len);

BTC_EXTERN void
btc_sha256_final(btc_sha256_t *ctx, uint8_t *out);

BTC_EXTERN void
btc_sha256(uint8_t *out, const void *data, size_t size);

/*
 * SHA512
 */

BTC_EXTERN void
btc_sha512_init(btc_sha512_t *ctx);

BTC_EXTERN void
btc_sha512_update(btc_sha512_t *ctx, const void *data, size_t len);

BTC_EXTERN void
btc_sha512_final(btc_sha512_t *ctx, uint8_t *out);

BTC_EXTERN void
btc_sha512(uint8_t *out, const void *data, size_t size);

/*
 * HMAC256
 */

BTC_EXTERN void
btc_hmac256_init(btc_hmac256_t *hmac, const uint8_t *key, size_t len);

BTC_EXTERN void
btc_hmac256_update(btc_hmac256_t *hmac, const void *data, size_t len);

BTC_EXTERN void
btc_hmac256_final(btc_hmac256_t *hmac, uint8_t *out);

/*
 * HMAC512
 */

BTC_EXTERN void
btc_hmac512_init(btc_hmac512_t *hmac, const uint8_t *key, size_t len);

BTC_EXTERN void
btc_hmac512_update(btc_hmac512_t *hmac, const void *data, size_t len);

BTC_EXTERN void
btc_hmac512_final(btc_hmac512_t *hmac, uint8_t *out);

/*
 * PBKDF256
 */

BTC_EXTERN void
btc_pbkdf256_derive(uint8_t *out,
                    const uint8_t *pass,
                    size_t pass_len,
                    const uint8_t *salt,
                    size_t salt_len,
                    uint32_t iter,
                    size_t len);

/*
 * PBKDF512
 */

BTC_EXTERN void
btc_pbkdf512_derive(uint8_t *out,
                    const uint8_t *pass,
                    size_t pass_len,
                    const uint8_t *salt,
                    size_t salt_len,
                    uint32_t iter,
                    size_t len);

#ifdef __cplusplus
}
#endif

#endif /* BTC_HASH_H */
