/*!
 * address.h - address for mako
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifndef BTC_ADDRESS_H
#define BTC_ADDRESS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "common.h"
#include "impl.h"
#include "types.h"

/*
 * Constants
 */

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

BTC_EXTERN uint32_t
btc_address_hash(const btc_address_t *x);

BTC_EXTERN int
btc_address_equal(const btc_address_t *x, const btc_address_t *y);

BTC_EXTERN int
btc_address_compare(const btc_address_t *x, const btc_address_t *y);

BTC_EXTERN int
btc_address_is_p2pkh(const btc_address_t *addr);

BTC_EXTERN int
btc_address_is_p2sh(const btc_address_t *addr);

BTC_EXTERN int
btc_address_is_p2wpkh(const btc_address_t *addr);

BTC_EXTERN int
btc_address_is_p2wsh(const btc_address_t *addr);

BTC_EXTERN int
btc_address_is_program(const btc_address_t *addr);

BTC_EXTERN void
btc_address_set_p2pk(btc_address_t *addr, const uint8_t *key, size_t length);

BTC_EXTERN void
btc_address_set_p2pkh(btc_address_t *addr, const uint8_t *hash);

BTC_EXTERN void
btc_address_set_p2sh(btc_address_t *addr, const uint8_t *hash);

BTC_EXTERN void
btc_address_set_p2wpk(btc_address_t *addr, const uint8_t *key, size_t length);

BTC_EXTERN void
btc_address_set_p2wpkh(btc_address_t *addr, const uint8_t *hash);

BTC_EXTERN void
btc_address_set_p2wsh(btc_address_t *addr, const uint8_t *hash);

BTC_EXTERN int
btc_address_set_program(btc_address_t *addr, const btc_program_t *program);

BTC_EXTERN void
btc_address_get_program(btc_program_t *program, const btc_address_t *addr);

BTC_EXTERN int
btc_address_set_script(btc_address_t *addr, const btc_script_t *script);

BTC_EXTERN void
btc_address_get_script(btc_script_t *script, const btc_address_t *addr);

BTC_EXTERN int
btc_address_set_str(btc_address_t *addr,
                    const char *str,
                    const btc_network_t *network);

BTC_EXTERN void
btc_address_get_str(char *str,
                    const btc_address_t *addr,
                    const btc_network_t *network);

BTC_EXTERN void
btc_address_inspect(const btc_address_t *addr, const btc_network_t *network);

#ifdef __cplusplus
}
#endif

#endif /* BTC_ADDRESS_H */
