/*!
 * t-stub.c - stub test for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <mako/crypto/rand.h>

#include <mako/address.h>
#include <mako/consensus.h>
#include <mako/network.h>
#include <mako/tx.h>
#include <mako/util.h>

#include <wallet/iterator.h>
#include <wallet/wallet.h>

#include "lib/tests.h"

static btc_tx_t *
create_funding(const btc_address_t *addr, int coins) {
  btc_tx_t *tx = btc_tx_create();
  uint8_t hash[32];

  btc_getrandom(hash, 32);

  btc_tx_add_input(tx, hash, 0);
  btc_tx_add_output(tx, addr, coins * BTC_COIN);

  btc_tx_refresh(tx);

  return tx;
}

static btc_tx_t *
create_tbs(const btc_address_t *addr, int coins) {
  btc_tx_t *tx = btc_tx_create();
  btc_tx_add_output(tx, addr, coins * BTC_COIN);
  return tx;
}

static void
test_simple(void) {
  const btc_network_t *network = btc_mainnet;
  btc_wallet_t *w = btc_wallet_create(network, 0);
  btc_address_t addr;
  btc_balance_t bal;
  btc_tx_t *tx;
  size_t i;

  ASSERT(btc_wallet_open(w, BTC_PREFIX));

  for (i = 0; i < 100; i++) {
    ASSERT(btc_wallet_receive(&addr, w, 0));

    tx = create_funding(&addr, 50);

    ASSERT(btc_wallet_add_tx(w, tx));

    btc_tx_destroy(tx);
  }

  ASSERT(btc_wallet_balance(&bal, w, 0));
  ASSERT(bal.tx == 100);
  ASSERT(bal.coin == 100);
  ASSERT(bal.confirmed == 0);
  ASSERT(bal.unconfirmed == 5000 * BTC_COIN);

  ASSERT(btc_wallet_create_account(w, "foobar", -1));

  {
    ASSERT(btc_wallet_receive(&addr, w, 1));

    tx = create_tbs(&addr, 225);

    ASSERT(btc_wallet_send(w, 0, NULL, tx));

    btc_tx_destroy(tx);
  }

  ASSERT(btc_wallet_balance(&bal, w, 0));
  ASSERT(bal.tx == 101);
  ASSERT(bal.coin == 96);
  ASSERT(bal.confirmed == 0);
  ASSERT(bal.unconfirmed >= 4774 * BTC_COIN);
  ASSERT(bal.unconfirmed <= 4775 * BTC_COIN);

  ASSERT(btc_wallet_balance(&bal, w, 1));
  ASSERT(bal.tx == 1);
  ASSERT(bal.coin == 1);
  ASSERT(bal.confirmed == 0);
  ASSERT(bal.unconfirmed == 225 * BTC_COIN);

  btc_wallet_close(w);
  btc_wallet_destroy(w);

  btc_rimraf(BTC_PREFIX);
}

int main(void) {
  test_simple();
  return 0;
}
