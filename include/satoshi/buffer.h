/*!
 * buffer.h - buffer for libsatoshi
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef BTC_BUFFER_H
#define BTC_BUFFER_H

#include <stddef.h>
#include <stdint.h>
#include "common.h"
#include "impl.h"
#include "types.h"

/*
 * Buffer
 */

BTC_DEFINE_SERIALIZABLE_OBJECT(btc_buffer, BTC_EXTERN)

BTC_EXTERN void
btc_buffer_init(btc_buffer_t *z);

BTC_EXTERN void
btc_buffer_clear(btc_buffer_t *z);

BTC_EXTERN uint8_t *
btc_buffer_grow(btc_buffer_t *z, size_t zn);

BTC_EXTERN uint8_t *
btc_buffer_resize(btc_buffer_t *z, size_t zn);

BTC_EXTERN void
btc_buffer_set(btc_buffer_t *z, const uint8_t *xp, size_t xn);

BTC_EXTERN void
btc_buffer_copy(btc_buffer_t *z, const btc_buffer_t *x);

BTC_EXTERN int
btc_buffer_equal(const btc_buffer_t *x, const btc_buffer_t *y);

BTC_EXTERN size_t
btc_buffer_size(const btc_buffer_t *x);

BTC_EXTERN uint8_t *
btc_buffer_write(uint8_t *zp, const btc_buffer_t *x);

BTC_EXTERN int
btc_buffer_read(btc_buffer_t *z, const uint8_t **xp, size_t *xn);

BTC_EXTERN void
btc_buffer_update(btc__hash256_t *ctx, const btc_buffer_t *x);

#endif /* BTC_BUFFER_H */
