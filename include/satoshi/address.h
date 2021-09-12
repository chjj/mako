/*!
 * address.h - address for libsatoshi
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef BTC_ADDRESS_H
#define BTC_ADDRESS_H

#include <stddef.h>
#include <stdint.h>
#include "common.h"
#include "impl.h"
#include "types.h"

/*
 * Address
 */

BTC_DEFINE_OBJECT(btc_address, BTC_EXTERN)

BTC_EXTERN void
btc_address_init(btc_address_t *z);

BTC_EXTERN void
btc_address_clear(btc_address_t *z);

BTC_EXTERN void
btc_address_copy(btc_address_t *z, const btc_address_t *x);

BTC_EXTERN int
btc_address_set_str(btc_address_t *addr, const char *str, const char *expect);

BTC_EXTERN int
btc_address_get_str(char *str, const btc_address_t *addr, const char *hrp);

#endif /* BTC_ADDRESS_H */
