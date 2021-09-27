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
#include "map/map.h"

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
  khiter_t it = kh_begin(coins->map);

  for (; it != kh_end(coins->map); it++) {
    if (!kh_exist(coins->map, it))
      continue;

    btc_coin_destroy(kh_value(coins->map, it));
  }

  kh_destroy(coins, coins->map);

  free(coins);
}

static btc_coin_t *
btc_coins_get(btc_coins_t *coins, uint32_t index) {
  khiter_t it = kh_get(coins, coins->map, index);

  if (it == kh_end(coins->map))
    return NULL;

  return kh_value(coins->map, it);
}

static void
btc_coins_put(btc_coins_t *coins, uint32_t index, btc_coin_t *coin) {
  int ret = -1;
  khiter_t it = kh_put(coins, coins->map, index, &ret);

  CHECK(ret != -1);

  /* It might be better to free `coin` in this
     situation. This call could break things if
     the coin in the bucket is present in the
     undo vector. Emphasis on "could": the code
     is currently structured in such a way that
     this should be impossible (short of a txid
     collision). */
  if (ret == 0)
    btc_coin_destroy(kh_value(coins->map, it));

  kh_value(coins->map, it) = coin;
}

/*
 * Coin View
 */

KHASH_INIT(view, const uint8_t *, btc_coins_t *, 1, kh_hash_hash_func,
                                                    kh_hash_hash_equal)

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
  khiter_t it = kh_begin(view->map);

  for (; it != kh_end(view->map); it++) {
    if (!kh_exist(view->map, it))
      continue;

    btc_coins_destroy(kh_value(view->map, it));
  }

  kh_destroy(view, view->map);

  view->undo.length = 0; /* Do not double-free coins. */

  btc_undo_clear(&view->undo);

  free(view);
}

static btc_coins_t *
btc_view_coins(btc__view_t *view, const uint8_t *hash) {
  khiter_t it = kh_get(view, view->map, hash);

  if (it == kh_end(view->map))
    return NULL;

  return kh_value(view->map, it);
}

static btc_coins_t *
btc_view_ensure(btc__view_t *view, const uint8_t *hash) {
  int ret = -1;
  khiter_t it = kh_put(view, view->map, hash, &ret);
  btc_coins_t *coins;

  CHECK(ret != -1);

  if (ret == 0) {
    coins = kh_value(view->map, it);
  } else {
    coins = btc_coins_create();

    memcpy(coins->hash, hash, 32);

    kh_key(view->map, it) = coins->hash;
    kh_value(view->map, it) = coins;
  }

  return coins;
}

int
btc_view_has(btc__view_t *view, const btc_outpoint_t *outpoint) {
  return btc_view_get(view, outpoint) != NULL;
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
               btc_coin_read_cb *read_coin,
               void *arg1,
               void *arg2) {
  const btc_outpoint_t *prevout;
  btc_coins_t *coins;
  btc_coin_t *coin;
  size_t i;

  for (i = 0; i < tx->inputs.length; i++) {
    prevout = &tx->inputs.items[i]->prevout;
    coins = btc_view_ensure(view, prevout->hash);
    coin = btc_coins_get(coins, prevout->index);

    if (coin == NULL) {
      coin = read_coin(prevout, arg1, arg2);

      if (coin == NULL)
        return 0;

      btc_coins_put(coins, prevout->index, coin);
    }

    if (coin->spent)
      return 0;

    coin->spent = 1;

    btc_undo_push(&view->undo, coin);
  }

  return 1;
}

int
btc_view_fill(btc__view_t *view,
              const btc_tx_t *tx,
              btc_coin_read_cb *read_coin,
              void *arg1,
              void *arg2) {
  const btc_outpoint_t *prevout;
  btc_coins_t *coins;
  btc_coin_t *coin;
  int ret = 1;
  size_t i;

  for (i = 0; i < tx->inputs.length; i++) {
    prevout = &tx->inputs.items[i]->prevout;
    coins = btc_view_ensure(view, prevout->hash);
    coin = btc_coins_get(coins, prevout->index);

    if (coin == NULL) {
      coin = read_coin(prevout, arg1, arg2);

      if (coin == NULL) {
        ret = 0;
        continue;
      }

      btc_coins_put(coins, prevout->index, coin);
    }
  }

  return ret;
}

void
btc_view_add(btc__view_t *view, const btc_tx_t *tx, int32_t height, int spent) {
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

void
btc_view_iterate(btc_viewiter_t *iter, btc__view_t *view) {
  iter->view = view;
  iter->itv = kh_begin(view->map);
  iter->itc = 0;
  iter->coins = NULL;
  iter->hash = NULL;
  iter->index = 0;
}

int
btc_view_next(const btc_coin_t **coin, btc_viewiter_t *iter) {
  btc__view_t *view = iter->view;

  for (;;) {
    if (iter->coins == NULL) {
      for (; iter->itv != kh_end(view->map); iter->itv++) {
        if (kh_exist(view->map, iter->itv)) {
          iter->coins = kh_value(view->map, iter->itv);
          iter->itv++;
          break;
        }
      }

      if (iter->coins == NULL)
        break;

      iter->itc = kh_begin(iter->coins->map);
    }

    for (; iter->itc != kh_end(iter->coins->map); iter->itc++) {
      if (kh_exist(iter->coins->map, iter->itc)) {
        iter->hash = iter->coins->hash;
        iter->index = kh_key(iter->coins->map, iter->itc);
        *coin = kh_value(iter->coins->map, iter->itc);
        iter->itc++;
        return 1;
      }
    }

    iter->coins = NULL;
  }

  return 0;
}

btc_undo_t *
btc_view_undo(btc__view_t *view) {
  return &view->undo;
}
