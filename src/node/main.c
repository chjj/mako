/*!
 * main.c - main entry point for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <io/core.h>
#include <node/node.h>
#include <satoshi/network.h>

int
main(int argc, char **argv) {
  btc_node_t *node;

  if (argc < 2)
    return 1;

  btc_net_startup();

  node = btc_node_create(btc_mainnet);

  if (!btc_node_open(node, argv[1], UINT64_C(16) << 30)) {
    btc_node_destroy(node);
    btc_net_cleanup();
    return 1;
  }

  btc_node_start(node);

  btc_net_cleanup();

  return 0;
}
