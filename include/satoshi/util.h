/*!
 * util.h - util for libsatoshi
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef BTC_UTIL_H
#define BTC_UTIL_H

#include <stddef.h>
#include <stdint.h>
#include "common.h"
#include "impl.h"
#include "types.h"

/*
 * Misc
 */

BTC_EXTERN int
btc_hash_compare(const uint8_t *x, const uint8_t *y);

/*
 * Compact
 */

BTC_EXTERN int
btc_compact_export(uint8_t *target, uint32_t bits);

BTC_EXTERN uint32_t
btc_compact_import(const uint8_t *target);

#endif /* BTC_UTIL_H */
