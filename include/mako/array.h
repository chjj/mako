/*!
 * array.h - integer vector for mako
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifndef BTC_ARRAY_H
#define BTC_ARRAY_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include "common.h"
#include "impl.h"
#include "types.h"

/*
 * Integer Vector
 */

BTC_DEFINE_OBJECT(btc_array, BTC_EXTERN)

BTC_EXTERN void
btc_array_init(btc_array_t *z);

BTC_EXTERN void
btc_array_clear(btc_array_t *z);

BTC_EXTERN void
btc_array_reset(btc_array_t *z);

BTC_EXTERN void
btc_array_grow(btc_array_t *z, size_t zn);

BTC_EXTERN void
btc_array_push(btc_array_t *z, int64_t x);

BTC_EXTERN int64_t
btc_array_pop(btc_array_t *z);

BTC_EXTERN int64_t
btc_array_top(const btc_array_t *z);

BTC_EXTERN void
btc_array_resize(btc_array_t *z, size_t zn);

BTC_EXTERN void
btc_array_copy(btc_array_t *z, const btc_array_t *x);

#ifdef __cplusplus
}
#endif

#endif /* BTC_ARRAY_H */
