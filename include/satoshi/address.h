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
#include "types.h"

enum btc_address_type {
  BTC_ADDRESS_P2PKH,
  BTC_ADDRESS_P2SH,
  BTC_ADDRESS_WITNESS
};

#define BTC_ADDRESS_MAXLEN 90

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
btc_address_set_str(btc_address_t *addr,
                    const char *str,
                    const struct btc_network_s *network);

BTC_EXTERN void
btc_address_get_str(char *str,
                    const btc_address_t *addr,
                    const struct btc_network_s *network);

BTC_EXTERN int
btc_address_set_script(btc_address_t *addr, const btc_script_t *script);

BTC_EXTERN void
btc_address_get_script(btc_script_t *script, const btc_address_t *addr);

BTC_EXTERN int
btc_address_set_program(btc_address_t *addr, const btc_program_t *program);

BTC_EXTERN void
btc_address_get_program(btc_program_t *program, const btc_address_t *addr);

#endif /* BTC_ADDRESS_H */
