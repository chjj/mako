/*!
 * view.c - view for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <satoshi/coins.h>
#include <satoshi/tx.h>
#include "impl.h"
#include "internal.h"
#include "map.h"

/*
 * Coins
 */

KHASH_MAP_INIT_INT(coins, btc_coin_t *)

typedef struct btc_coins_s {
  uint8_t hash[32];
  khash_t(coins) *map;
} btc_coins_t;

static btc_coins_t *
btc_coins_create(void) {
  btc_coins_t *coins = (btc_coins_t *)malloc(sizeof(btc_coins_t));

  CHECK(coins != NULL);

  coins->map = kh_init(coins);

  CHECK(coins->map != NULL);

  return coins;
}

static void
btc_coins_destroy(btc_coins_t *coins) {
  khiter_t iter = kh_begin(coins->map);
  btc_coin_t *val;

  for (; iter != kh_end(coins->map); iter++) {
    if (kh_exist(coins->map, iter)) {
      val = kh_value(coins->map, iter);

      if (val != NULL)
        btc_coin_destroy(val);

      kh_value(coins->map, iter) = NULL;
    }
  }

  kh_destroy(coins, coins->map);

  free(coins);
}

static btc_coin_t *
btc_coins_get(btc_coins_t *coins, uint32_t index) {
  khiter_t iter = kh_get(coins, coins->map, index);

  if (iter == kh_end(coins->map))
    return 0;

  return kh_value(coins->map, iter);
}

static void
btc_coins_put(btc_coins_t *coins, uint32_t index, btc_coin_t *coin) {
  int ret = -1;
  khiter_t iter = kh_put(coins, coins->map, index, &ret);
  btc_coin_t *val;

  CHECK(ret != -1);

  if (ret == 0) {
    val = kh_value(coins->map, iter);

    if (val != NULL)
      btc_coin_destroy(val);
  }

  kh_value(coins->map, iter) = coin;
}

/*
 * Coin View
 */

KHASH_MAP_INIT_CONST_HASH(view, btc_coins_t *)

typedef struct btc_view_s {
  khash_t(view) *map;
  btc_undo_t undo;
} btc__view_t;

btc__view_t *
btc_view_create(void) {
  btc__view_t *view = (btc__view_t *)malloc(sizeof(btc__view_t));

  CHECK(view != NULL);

  view->map = kh_init(view);

  CHECK(view->map != NULL);

  btc_undo_init(&view->undo);

  return view;
}

void
btc_view_destroy(btc__view_t *view) {
  khiter_t iter = kh_begin(view->map);
  btc_coins_t *val;

  for (; iter != kh_end(view->map); iter++) {
    if (kh_exist(view->map, iter)) {
      val = kh_value(view->map, iter);

      if (val != NULL)
        btc_coins_destroy(val);

      kh_value(view->map, iter) = NULL;
    }
  }

  kh_destroy(view, view->map);

  btc_undo_clear(&view->undo);

  free(view);
}

static btc_coins_t *
btc_view_coins(btc__view_t *view, const uint8_t *hash) {
  khiter_t iter = kh_get(view, view->map, hash);

  if (iter == kh_end(view->map))
    return NULL;

  return kh_value(view->map, iter);
}

static btc_coins_t *
btc_view_ensure(btc__view_t *view, const uint8_t *hash) {
  int ret = -1;
  khiter_t iter = kh_put(view, view->map, hash, &ret);
  btc_coins_t *coins;

  CHECK(ret != -1);

  if (ret) {
    coins = btc_coins_create();

    memcpy(coins->hash, hash, 32);

    kh_key(view->map, iter) = coins->hash;
    kh_value(view->map, iter) = coins;
  } else {
    coins = kh_value(view->map, iter);

    CHECK(coins != NULL);
  }

  return coins;
}

const btc_coin_t *
btc_view_get(btc__view_t *view, const btc_outpoint_t *outpoint) {
  btc_coins_t *coins = btc_view_coins(view, outpoint->hash);

  if (coins == NULL)
    return NULL;

  return btc_coins_get(coins, outpoint->index);
}

void
btc_view_put(btc__view_t *view,
             const btc_outpoint_t *outpoint,
             btc_coin_t *coin) {
  btc_coins_t *coins = btc_view_ensure(view, outpoint->hash);
  btc_coins_put(coins, outpoint->index, coin);
}

int
btc_view_spend(btc__view_t *view,
               const btc_tx_t *tx,
               btc_coin_t *(*read_coin)(void *,
                                        void *,
                                        const btc_outpoint_t *),
               void *ctx,
               void *arg) {
  const btc_outpoint_t *prevout;
  btc_coins_t *coins;
  btc_coin_t *coin;
  size_t i;

  for (i = 0; i < tx->inputs.length; i++) {
    prevout = &tx->inputs.items[i]->prevout;
    coins = btc_view_ensure(view, prevout->hash);
    coin = btc_coins_get(coins, prevout->index);

    if (coin == NULL) {
      coin = read_coin(ctx, arg, prevout);

      if (coin == NULL)
        return 0;

      btc_coins_put(coins, prevout->index, coin);
    }

    if (coin->spent)
      return 0;

    coin->spent = 1;

    /* TODO: Maybe use a shallow vector for this? */
    btc_undo_push(&view->undo, btc_coin_clone(coin));
  }

  return 1;
}

void
btc_view_add(btc__view_t *view, const btc_tx_t *tx, uint32_t height, int spent) {
  uint8_t hash[32];
  btc_coins_t *coins;
  btc_coin_t *coin;
  size_t i;

  btc_tx_txid(hash, tx);

  coins = btc_view_ensure(view, hash);

  for (i = 0; i < tx->outputs.length; i++) {
    coin = btc_tx_coin(tx, i, height);
    coin->spent = spent;

    btc_coins_put(coins, i, coin);
  }
}

int
btc_view_iterate(btc__view_t *view,
                 int (*cb)(void *,
                           void *,
                           const uint8_t *,
                           uint32_t,
                           const btc_coin_t *),
                 void *ctx,
                 void *arg) {
  khiter_t view_iter = kh_begin(view->map);
  khiter_t coins_iter;
  btc_coins_t *coins;
  int rc;

  for (; view_iter != kh_end(view->map); view_iter++) {
    if (!kh_exist(view->map, view_iter))
      continue;

    coins = kh_value(view->map, view_iter);
    coins_iter = kh_begin(coins->map);

    for (; coins_iter != kh_end(coins->map); coins_iter++) {
      if (!kh_exist(coins->map, coins_iter))
        continue;

      rc = cb(ctx, arg, coins->hash,
              kh_key(coins->map, coins_iter),
              kh_value(coins->map, coins_iter));

      if (rc == 0)
        return 0;
    }
  }

  return 1;
}

btc_undo_t *
btc_view_undo(btc__view_t *view) {
  return &view->undo;
}
