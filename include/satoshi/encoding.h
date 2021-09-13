/*!
 * encoding.h - string encodings for libsatoshi
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef BTC_ENCODING_H
#define BTC_ENCODING_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "common.h"

/*
 * Base58
 */

BTC_EXTERN int
btc_base58_encode(char *dst, size_t *dstlen,
                  const uint8_t *src, size_t srclen);

BTC_EXTERN int
btc_base58_decode(uint8_t *dst, size_t *dstlen,
                  const char *src, size_t srclen);

BTC_EXTERN int
btc_base58_test(const char *str, size_t len);

/*
 * Bech32
 */

BTC_EXTERN int
btc_bech32_encode(char *addr,
                  const char *hrp,
                  unsigned int version,
                  const uint8_t *hash,
                  size_t hash_len);

BTC_EXTERN int
btc_bech32_decode(char *hrp,
                  unsigned int *version,
                  uint8_t *hash,
                  size_t *hash_len,
                  const char *addr);

BTC_EXTERN int
btc_bech32_test(const char *addr);

#ifdef __cplusplus
}
#endif

#endif /* BTC_ENCODING_H */
