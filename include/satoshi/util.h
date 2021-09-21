/*!
 * util.h - util for libsatoshi
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef BTC_UTIL_H
#define BTC_UTIL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "common.h"

/*
 * Compact
 */

BTC_EXTERN int
btc_compact_export(uint8_t *target, uint32_t bits);

BTC_EXTERN uint32_t
btc_compact_import(const uint8_t *target);

/*
 * Murmur3
 */

BTC_EXTERN uint32_t
btc_murmur3_sum(const uint8_t *data, size_t len, uint32_t seed);

BTC_EXTERN uint32_t
btc_murmur3_tweak(const uint8_t *data, size_t len, uint32_t n, uint32_t tweak);

/*
 * Memory Zero
 */

BTC_EXTERN void
btc_memzero(void *ptr, size_t len);

/*
 * Memory Compare
 */

BTC_EXTERN int
btc_memcmp(const void *x, const void *y, size_t n);

/*
 * Memory Equal
 */

BTC_EXTERN int
btc_memequal(const void *x, const void *y, size_t n);

/*
 * Memory XOR
 */

BTC_EXTERN void
btc_memxor(void *z, const void *x, size_t n);

BTC_EXTERN void
btc_memxor3(void *z, const void *x, const void *y, size_t n);

/*
 * Hash
 */

BTC_EXTERN void
btc_hash_init(uint8_t *zp);

BTC_EXTERN void
btc_hash_copy(uint8_t *zp, const uint8_t *xp);

BTC_EXTERN uint8_t *
btc_hash_clone(const uint8_t *xp);

BTC_EXTERN int
btc_hash_compare(const uint8_t *xp, const uint8_t *yp);

BTC_EXTERN int
btc_hash_equal(const uint8_t *xp, const uint8_t *yp);

BTC_EXTERN int
btc_hash_is_null(const uint8_t *xp);

BTC_EXTERN int
btc_hash_import(uint8_t *zp, const char *xp);

BTC_EXTERN void
btc_hash_export(char *zp, const uint8_t *xp);

/*
 * Time
 */

BTC_EXTERN int64_t
btc_now(void);

#ifdef __cplusplus
}
#endif

#endif /* BTC_UTIL_H */
