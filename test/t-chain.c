/*!
 * t-chain.c - chain test for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stddef.h>
#include <string.h>
#include <node/chain.h>
#include <mako/block.h>
#include <mako/network.h>
#include "lib/tests.h"
#include "data/chain_vectors_main.h"
#include "data/chain_vectors_testnet.h"

static void
test_chain(const btc_network_t *network, const char **vectors, size_t length) {
  unsigned int flags = BTC_BLOCK_DEFAULT_FLAGS;
  btc_chain_t *chain = btc_chain_create(network);
  unsigned char data[65536];
  btc_block_t block;
  size_t i;

  btc_clean(BTC_PREFIX);

  btc_chain_set_mapsize(chain, 20 << 20);

  ASSERT(btc_chain_open(chain, BTC_PREFIX, 0));

  for (i = 0; i < length; i++) {
    size_t size = sizeof(data);

    hex_decode(data, &size, vectors[i]);

    btc_block_init(&block);

    ASSERT(btc_block_import(&block, data, size));
    ASSERT(btc_chain_add(chain, &block, flags, -1));

    btc_block_clear(&block);
  }

  btc_chain_close(chain);
  btc_chain_destroy(chain);

  btc_clean(BTC_PREFIX);
}

int
main(void) {
  test_chain(btc_mainnet, chain_vectors_main,
                          lengthof(chain_vectors_main));

  test_chain(btc_testnet, chain_vectors_testnet,
                          lengthof(chain_vectors_testnet));

  return 0;
}
