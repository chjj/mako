/*!
 * siphash.h - siphash for libsatoshi
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef BTC_SIPHASH_H
#define BTC_SIPHASH_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "../common.h"

/*
 * Siphash
 */

BTC_EXTERN uint64_t
btc_siphash_sum(const uint8_t *data, size_t size, const uint8_t *key);

BTC_EXTERN uint64_t
btc_siphash_mod(const uint8_t *data,
                size_t size,
                const uint8_t *key,
                uint64_t mod);

#ifdef __cplusplus
}
#endif

#endif /* BTC_SIPHASH_H */
