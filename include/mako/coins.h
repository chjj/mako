/*!
 * coins.h - coins for mako
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
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
 * Types
 */

struct btc_coins_s {
  uint8_t hash[32];
  btc_intmap_t map;
};

struct btc_view_s {
  btc_hashmap_t map;
  btc_undo_t undo;
};

typedef btc_coin_t *btc_coin_read_cb(const btc_outpoint_t *prevout, void *arg);

/*
 * Coin
 */

BTC_DEFINE_SERIALIZABLE_REFOBJ(btc_coin, BTC_EXTERN)

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

BTC_EXTERN void
btc_coin_inspect(const btc_coin_t *coin, const btc_network_t *network);

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

BTC_EXTERN int
btc_view_has(const btc_view_t *view, const btc_outpoint_t *outpoint);

BTC_EXTERN const btc_coin_t *
btc_view_get(const btc_view_t *view, const btc_outpoint_t *outpoint);

BTC_EXTERN void
btc_view_put(btc_view_t *view,
             const btc_outpoint_t *outpoint,
             btc_coin_t *coin);

BTC_EXTERN int
btc_view_spend(btc_view_t *view,
               const btc_tx_t *tx,
               btc_coin_read_cb *read_coin,
               void *arg);

BTC_EXTERN int
btc_view_fill(btc_view_t *view,
              const btc_tx_t *tx,
              btc_coin_read_cb *read_coin,
              void *arg);

BTC_EXTERN void
btc_view_add(btc_view_t *view, const btc_tx_t *tx, int32_t height, int spent);

#ifdef __cplusplus
}
#endif

#endif /* BTC_COINS_H */
