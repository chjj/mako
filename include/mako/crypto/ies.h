/*!
 * ies.c - ies for mako
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifndef BTC_IES_H
#define BTC_IES_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "../common.h"

/*
 * Macros
 */

#define BTC_SECRETBOX_SEAL_SIZE(len) (16 + (len))
#define BTC_SECRETBOX_OPEN_SIZE(len) ((len) < 16 ? 0 : (len) - 16)

/*
 * Secret Box
 */

BTC_EXTERN void
btc_secretbox_seal(uint8_t *sealed,
                   const uint8_t *msg,
                   size_t msg_len,
                   const uint8_t *key,
                   const uint8_t *nonce);

BTC_EXTERN int
btc_secretbox_open(uint8_t *msg,
                   const uint8_t *sealed,
                   size_t sealed_len,
                   const uint8_t *key,
                   const uint8_t *nonce);

BTC_EXTERN void
btc_secretbox_derive(uint8_t *key, const uint8_t *secret);

#ifdef __cplusplus
}
#endif

#endif /* BTC_IES_H */
