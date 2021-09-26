/*!
 * rand.h - RNG for libsatoshi
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef BTC_RAND_H
#define BTC_RAND_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "../common.h"

/*
 * Random
 */

BTC_EXTERN int
btc_getentropy(void *dst, size_t size);

BTC_EXTERN void
btc_getrandom(void *dst, size_t size);

BTC_EXTERN uint32_t
btc_random(void);

BTC_EXTERN uint32_t
btc_uniform(uint32_t max);

BTC_EXTERN uint64_t
btc_nonce(void);

#ifdef __cplusplus
}
#endif

#endif /* BTC_RAND_H */
