/*!
 * view.c - view for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <mako/coins.h>
#include <mako/map.h>
#include <mako/script.h>
#include <mako/tx.h>
#include <mako/util.h>

#include "impl.h"
#include "internal.h"

/*
 * Coins
 */

static btc_coins_t *
btc_coins_create(void) {
  btc_coins_t *coins = btc_malloc(sizeof(btc_coins_t));

  btc_intmap_init(&coins->map);

  return coins;
}

static void
btc_coins_destroy(btc_coins_t *coins) {
  btc_mapiter_t it;

  btc_map_each(&coins->map, it)
    btc_coin_destroy(coins->map.vals[it]);

  btc_intmap_clear(&coins->map);

  btc_free(coins);
}

static btc_coin_t *
btc_coins_get(const btc_coins_t *coins, uint32_t index) {
  return btc_intmap_get(&coins->map, index);
}

static void
btc_coins_put(btc_coins_t *coins, uint32_t index, btc_coin_t *coin) {
  btc_mapiter_t it;
  int exists;

  it = btc_intmap_insert(&coins->map, index, &exists);

  if (exists)
    btc_coin_destroy(coins->map.vals[it]);

  coins->map.vals[it] = coin;
}

/*
 * Coin View
 */

btc_view_t *
btc_view_create(void) {
  btc_view_t *view = btc_malloc(sizeof(btc_view_t));
  btc_view_init(view);
  return view;
}

void
btc_view_destroy(btc_view_t *view) {
  btc_view_clear(view);
  btc_free(view);
}

void
btc_view_init(btc_view_t *view) {
  btc_hashmap_init(&view->map);
  btc_undo_init(&view->undo);
}

void
btc_view_clear(btc_view_t *view) {
  btc_mapiter_t it;

  btc_map_each(&view->map, it)
    btc_coins_destroy(view->map.vals[it]);

  btc_hashmap_clear(&view->map);
  btc_undo_clear(&view->undo);
}

void
btc_view_reset(btc_view_t *view) {
  btc_mapiter_t it;

  btc_map_each(&view->map, it)
    btc_coins_destroy(view->map.vals[it]);

  btc_hashmap_reset(&view->map);
  btc_undo_reset(&view->undo);
}

static btc_coins_t *
btc_view_coins(const btc_view_t *view, const uint8_t *hash) {
  return btc_hashmap_get(&view->map, hash);
}

static btc_coins_t *
btc_view_ensure(btc_view_t *view, const uint8_t *hash) {
  btc_coins_t *coins;
  btc_mapiter_t it;
  int exists;

  it = btc_hashmap_insert(&view->map, hash, &exists);

  if (exists) {
    coins = view->map.vals[it];
  } else {
    coins = btc_coins_create();

    btc_hash_copy(coins->hash, hash);

    view->map.keys[it] = coins->hash;
    view->map.vals[it] = coins;
  }

  return coins;
}

int
btc_view_has(const btc_view_t *view, const btc_outpoint_t *outpoint) {
  return btc_view_get(view, outpoint) != NULL;
}

const btc_coin_t *
btc_view_get(const btc_view_t *view, const btc_outpoint_t *outpoint) {
  btc_coins_t *coins = btc_view_coins(view, outpoint->hash);

  if (coins == NULL)
    return NULL;

  return btc_coins_get(coins, outpoint->index);
}

void
btc_view_put(btc_view_t *view,
             const btc_outpoint_t *outpoint,
             btc_coin_t *coin) {
  btc_coins_t *coins = btc_view_ensure(view, outpoint->hash);
  btc_coins_put(coins, outpoint->index, coin);
}

int
btc_view_spend(btc_view_t *view,
               const btc_tx_t *tx,
               btc_coin_read_cb *read_coin,
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
      coin = read_coin(prevout, arg);

      if (coin == NULL)
        return 0;

      btc_coins_put(coins, prevout->index, coin);
    }

    if (coin->spent)
      return 0;

    coin->spent = 1;

    btc_undo_push(&view->undo, btc_coin_ref(coin));
  }

  return 1;
}

int
btc_view_fill(btc_view_t *view,
              const btc_tx_t *tx,
              btc_coin_read_cb *read_coin,
              void *arg) {
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
      coin = read_coin(prevout, arg);

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
btc_view_add(btc_view_t *view, const btc_tx_t *tx, int32_t height, int spent) {
  const btc_output_t *output;
  btc_coins_t *coins;
  btc_coin_t *coin;
  size_t i;

  coins = btc_view_ensure(view, tx->hash);

  for (i = 0; i < tx->outputs.length; i++) {
    output = tx->outputs.items[i];

    if (btc_script_is_unspendable(&output->script))
      continue;

    coin = btc_tx_coin(tx, i, height);
    coin->spent = spent;

    btc_coins_put(coins, i, coin);
  }
}
