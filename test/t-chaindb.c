/*!
 * t-chaindb.c - chaindb test for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stddef.h>
#include <string.h>
#include <node/chaindb.h>
#include <satoshi/network.h>
#include "tests.h"

#ifndef BTC_PREFIX
#  define BTC_PREFIX "./tmp"
#endif

int main(void) {
  btc_chaindb_t *db = btc_chaindb_create(btc_mainnet);

  ASSERT(btc_chaindb_open(db, BTC_PREFIX, 20 << 20));

  btc_chaindb_close(db);
  btc_chaindb_destroy(db);

  return 0;
}
