/*!
 * t-chain.c - chain test for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stddef.h>
#include <string.h>
#include <node/chain.h>
#include <satoshi/block.h>
#include <satoshi/network.h>
#include "lib/tests.h"
#include "data/chain_vectors_main.h"

int main(void) {
  unsigned int flags = BTC_BLOCK_DEFAULT_FLAGS;
  btc_chain_t *chain = btc_chain_create(btc_mainnet);
  unsigned char data[4096];
  btc_block_t block;
  size_t i;

  btc_clean(BTC_PREFIX);

  btc_chain_set_mapsize(chain, 20 << 20);

  ASSERT(btc_chain_open(chain, BTC_PREFIX, 0));

  for (i = 0; i < lengthof(chain_vectors_main); i++) {
    size_t size = sizeof(data);

    hex_decode(data, &size, chain_vectors_main[i]);

    btc_block_init(&block);

    ASSERT(btc_block_import(&block, data, size));
    ASSERT(btc_chain_add(chain, &block, flags, -1));

    btc_block_clear(&block);
  }

  btc_chain_close(chain);
  btc_chain_destroy(chain);

  btc_clean(BTC_PREFIX);

  return 0;
}
