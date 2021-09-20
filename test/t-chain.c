#include <stddef.h>
#include <string.h>
#include <node/chain.h>
#include <satoshi/block.h>
#include <satoshi/network.h>
#include "tests.h"
#include "data/chain_vectors_main.h"

#ifndef BTC_PREFIX
#  define BTC_PREFIX "./tmp"
#endif

int main(void) {
  unsigned int flags = BTC_CHAIN_DEFAULT_FLAGS;
  btc_chain_t *chain = btc_chain_create(btc_mainnet);
  unsigned char data[4096];
  btc_block_t block;
  size_t i;

  ASSERT(btc_chain_open(chain, BTC_PREFIX, 20 << 20));

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

  return 0;
}
