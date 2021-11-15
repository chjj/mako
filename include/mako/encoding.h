/*!
 * encoding.h - string encodings for mako
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
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
 * Base16
 */

BTC_EXTERN void
btc_base16_encode(char *zp, const uint8_t *xp, size_t xn);

BTC_EXTERN int
btc_base16_decode(uint8_t *zp, const char *xp, size_t xn);

BTC_EXTERN int
btc_base16_test(const char *xp);

/*
 * Base16 (Little Endian)
 */

BTC_EXTERN void
btc_base16le_encode(char *zp, const uint8_t *xp, size_t xn);

BTC_EXTERN int
btc_base16le_decode(uint8_t *zp, const char *xp, size_t xn);

/*
 * Base58
 */

BTC_EXTERN void
btc_base58_encode(char *zp, const uint8_t *xp, size_t xn);

BTC_EXTERN int
btc_base58_decode(uint8_t *zp, size_t *zn, const char *xp, size_t xn);

BTC_EXTERN int
btc_base58_test(const char *xp);

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
