/*!
 * header.h - header for libsatoshi
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef BTC_HEADER_H
#define BTC_HEADER_H

#include <stddef.h>
#include <stdint.h>
#include "common.h"
#include "impl.h"
#include "types.h"

/*
 * Header
 */

BTC_DEFINE_SERIALIZABLE_OBJECT(btc_header, BTC_EXTERN)

BTC_EXTERN void
btc_header_init(btc_header_t *z);

BTC_EXTERN void
btc_header_clear(btc_header_t *z);

BTC_EXTERN void
btc_header_copy(btc_header_t *z, const btc_header_t *x);

BTC_EXTERN size_t
btc_header_size(const btc_header_t *x);

BTC_EXTERN uint8_t *
btc_header_write(uint8_t *zp, const btc_header_t *x);

BTC_EXTERN int
btc_header_read(btc_header_t *z, const uint8_t **xp, size_t *xn);

BTC_EXTERN void
btc_header_hash(uint8_t *hash, const btc_header_t *hdr);

BTC_EXTERN int
btc_header_verify(const btc_header_t *hdr);

#endif /* BTC_HEADER_H */
