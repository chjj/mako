/*!
 * bip39.h - bip39 for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef BTC_BIP39_H
#define BTC_BIP39_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "types.h"
#include "common.h"

/*
 * Constants
 */

/* Max words = 48, max word length = 8 */
#define BTC_PHRASE_MAX (48 * (8 + 1) - 1)
#define BTC_MNEMONIC_SIZE (1 + 48 * 2)

/*
 * Mnemonic
 */

BTC_EXTERN void
btc_mnemonic_init(btc_mnemonic_t *mn);

BTC_EXTERN void
btc_mnemonic_clear(btc_mnemonic_t *mn);

BTC_EXTERN void
btc_mnemonic_copy(btc_mnemonic_t *z, const btc_mnemonic_t *x);

BTC_EXTERN int
btc_mnemonic_equal(const btc_mnemonic_t *x, const btc_mnemonic_t *y);

BTC_EXTERN void
btc_mnemonic_set(btc_mnemonic_t *mn, const uint8_t *entropy, size_t length);

BTC_EXTERN void
btc_mnemonic_generate(btc_mnemonic_t *mn, unsigned int bits);

BTC_EXTERN int
btc_mnemonic_set_phrase(btc_mnemonic_t *mn, const char *phrase);

BTC_EXTERN void
btc_mnemonic_get_phrase(char *phrase, const btc_mnemonic_t *mn);

BTC_EXTERN void
btc_mnemonic_seed(uint8_t *seed, const btc_mnemonic_t *mn, const char *pass);

BTC_EXTERN size_t
btc_mnemonic_size(const btc_mnemonic_t *mn);

BTC_EXTERN uint8_t *
btc_mnemonic_write(uint8_t *zp, const btc_mnemonic_t *mn);

BTC_EXTERN int
btc_mnemonic_read(btc_mnemonic_t *mn, const uint8_t **xp, size_t *xn);

BTC_EXTERN size_t
btc_mnemonic_export(uint8_t *zp, const btc_mnemonic_t *mn);

BTC_EXTERN int
btc_mnemonic_import(btc_mnemonic_t *mn, const uint8_t *xp, size_t xn);

#ifdef __cplusplus
}
#endif

#endif /* BTC_BIP39_H */
