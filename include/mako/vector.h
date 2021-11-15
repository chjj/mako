/*!
 * vector.h - shallow vector for mako
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifndef BTC_VECTOR_H
#define BTC_VECTOR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include "common.h"
#include "impl.h"
#include "types.h"

/*
 * Vector
 */

BTC_DEFINE_OBJECT(btc_vector, BTC_EXTERN)

BTC_EXTERN void
btc_vector_init(btc_vector_t *z);

BTC_EXTERN void
btc_vector_clear(btc_vector_t *z);

BTC_EXTERN void
btc_vector_reset(btc_vector_t *z);

BTC_EXTERN void
btc_vector_grow(btc_vector_t *z, size_t zn);

BTC_EXTERN void
btc_vector_push(btc_vector_t *z, const void *x);

BTC_EXTERN void *
btc_vector_pop(btc_vector_t *z);

BTC_EXTERN void *
btc_vector_top(const btc_vector_t *z);

BTC_EXTERN void
btc_vector_resize(btc_vector_t *z, size_t zn);

BTC_EXTERN void
btc_vector_copy(btc_vector_t *z, const btc_vector_t *x);

#ifdef __cplusplus
}
#endif

#endif /* BTC_VECTOR_H */
