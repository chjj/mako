/*!
 * coins.h - coins for libsatoshi
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef BTC_COINS_H
#define BTC_COINS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "common.h"
#include "impl.h"
#include "types.h"

/*
 * Coin
 */

BTC_DEFINE_SERIALIZABLE_OBJECT(btc_coin, BTC_EXTERN)

BTC_EXTERN void
btc_coin_init(btc_coin_t *z);

BTC_EXTERN void
btc_coin_clear(btc_coin_t *z);

BTC_EXTERN void
btc_coin_copy(btc_coin_t *z, const btc_coin_t *x);

BTC_EXTERN size_t
btc_coin_size(const btc_coin_t *x);

BTC_EXTERN uint8_t *
btc_coin_write(uint8_t *zp, const btc_coin_t *x);

BTC_EXTERN int
btc_coin_read(btc_coin_t *z, const uint8_t **xp, size_t *xn);

/*
 * Undo Coins
 */

BTC_DEFINE_SERIALIZABLE_VECTOR(btc_undo, btc_coin, BTC_EXTERN)

/*
 * Coin View
 */

BTC_EXTERN btc_view_t *
btc_view_create(void);

BTC_EXTERN void
btc_view_destroy(btc_view_t *view);

BTC_EXTERN const btc_coin_t *
btc_view_get(btc_view_t *view, const btc_outpoint_t *outpoint);

BTC_EXTERN void
btc_view_put(btc_view_t *view,
             const btc_outpoint_t *outpoint,
             btc_coin_t *coin);

BTC_EXTERN int
btc_view_spend(btc_view_t *view,
               const btc_tx_t *tx,
               btc_coin_t *(*read_coin)(const btc_outpoint_t *prevout,
                                        void *arg1,
                                        void *arg2),
               void *arg1,
               void *arg2);

BTC_EXTERN void
btc_view_add(btc_view_t *view, const btc_tx_t *tx, uint32_t height, int spent);

BTC_EXTERN int
btc_view_iterate(btc_view_t *view,
                 int (*cb)(const uint8_t *hash,
                           uint32_t index,
                           const btc_coin_t *coin,
                           void *arg1,
                           void *arg2),
                 void *arg1,
                 void *arg2);

BTC_EXTERN btc_undo_t *
btc_view_undo(btc_view_t *view);

#ifdef __cplusplus
}
#endif

#endif /* BTC_COINS_H */
