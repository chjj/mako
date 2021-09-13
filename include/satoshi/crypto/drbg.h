/*!
 * drbg.h - hmac drbg implementation for libsatoshi
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef BTC_DRBG_H
#define BTC_DRBG_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "../common.h"
#include "types.h"

/*
 * HMAC-DRBG
 */

BTC_EXTERN void
btc_drbg_init(btc_drbg_t *drbg, const uint8_t *seed, size_t seed_len);

BTC_EXTERN void
btc_drbg_reseed(btc_drbg_t *drbg, const uint8_t *seed, size_t seed_len);

BTC_EXTERN void
btc_drbg_generate(btc_drbg_t *drbg, void *out, size_t len);

BTC_EXTERN void
btc_drbg_rng(void *out, size_t size, void *arg);

#ifdef __cplusplus
}
#endif

#endif /* BTC_DRBG_H */
