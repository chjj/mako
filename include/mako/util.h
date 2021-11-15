/*!
 * util.h - util for mako
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifndef BTC_UTIL_H
#define BTC_UTIL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "common.h"

/*
 * Constants
 */

#define BTC_PRECISION 8
#define BTC_AMOUNT_LEN (1 + (19 - BTC_PRECISION) + 1 + BTC_PRECISION)

/*
 * Amount
 */

BTC_EXTERN size_t
btc_amount_export(char *zp, int64_t x);

BTC_EXTERN int
btc_amount_import(int64_t *z, const char *xp);

BTC_EXTERN double
btc_amount_to_double(int64_t x);

BTC_EXTERN int
btc_amount_from_double(int64_t *z, double x);

BTC_EXTERN void
btc_amount_inspect(int64_t x);

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
 * String
 */

BTC_EXTERN size_t
btc_strnlen(const char *xp, size_t max);

/*
 * Hash
 */

#define btc_hash_init(zp) memset(zp, 0, 32)
#define btc_hash_copy(zp, xp) memcpy(zp, xp, 32)
#define btc_hash_equal(xp, yp) (memcmp(xp, yp, 32) == 0)

BTC_EXTERN uint8_t *
btc_hash_clone(const uint8_t *xp);

BTC_EXTERN int
btc_hash_compare(const uint8_t *xp, const uint8_t *yp);

BTC_EXTERN int
btc_hash_is_null(const uint8_t *xp);

BTC_EXTERN int
btc_hash_import(uint8_t *zp, const char *xp);

BTC_EXTERN void
btc_hash_export(char *zp, const uint8_t *xp);

BTC_EXTERN void
btc_hash_inspect(const uint8_t *xp);

/*
 * Time
 */

BTC_EXTERN int64_t
btc_now(void);

/*
 * PoW
 */

BTC_EXTERN double
btc_difficulty(uint32_t bits);

#ifdef __cplusplus
}
#endif

#endif /* BTC_UTIL_H */
