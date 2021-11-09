/*!
 * t-chaindb.c - chaindb test for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stddef.h>
#include <string.h>
#include <node/chaindb.h>
#include <satoshi/network.h>
#include "lib/tests.h"

int main(void) {
  btc_chaindb_t *db = btc_chaindb_create(btc_mainnet);

  btc_clean(BTC_PREFIX);

  btc_chaindb_set_mapsize(db, 20 << 20);

  ASSERT(btc_chaindb_open(db, BTC_PREFIX, BTC_CHAIN_DEFAULT_FLAGS));

  btc_chaindb_close(db);
  btc_chaindb_destroy(db);

  btc_clean(BTC_PREFIX);

  return 0;
}
