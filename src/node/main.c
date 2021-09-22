/*!
 * main.c - main entry point for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <node/node.h>
#include <satoshi/network.h>

int
main(int argc, char **argv) {
  btc_node_t *node;

  if (argc < 2)
    return 1;

  node = btc_node_create(btc_mainnet);

  if (!btc_node_open(node, argv[1], UINT64_C(16) << 30)) {
    btc_node_destroy(node);
    return 1;
  }

  btc_node_start(node);

  return 0;
}
