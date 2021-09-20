#include <stddef.h>
#include <string.h>
#include <node/chain.h>
#include <satoshi/network.h>
#include "tests.h"
#include "data/chain_vectors_main.h"

#ifndef BTC_PREFIX
#  define BTC_PREFIX "./tmp"
#endif

int main(void) {
  btc_chain_t *chain = btc_chain_create(btc_mainnet);

  ASSERT(btc_chain_open(chain, BTC_PREFIX, 20 << 20));

  btc_chain_close(chain);
  btc_chain_destroy(chain);

  return 0;
}
