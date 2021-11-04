/*!
 * main.c - main entry point for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <io/core.h>
#include <node/node.h>
#include <satoshi/config.h>

static int
get_config(btc_conf_t *args, int argc, char **argv) {
  char prefix[700];
  btc_conf_t conf;

  if (!btc_sys_datadir(prefix, sizeof(prefix), "satoshi")) {
    fprintf(stderr, "Could not find suitable datadir.\n");
    return 0;
  }

  btc_conf_parse(args, argv, argc, prefix, 0);
  btc_conf_read(&conf, args->config);
  btc_conf_merge(args, &conf);
  btc_conf_finalize(args, prefix);

  return 1;
}

int
main(int argc, char **argv) {
  uint64_t map_size;
  btc_node_t *node;
  btc_conf_t args;

  if (!get_config(&args, argc, argv))
    return EXIT_FAILURE;

  if (args.help) {
    fprintf(stderr, "RTFM.\n");
    return EXIT_FAILURE;
  }

  if (args.version) {
    printf("0.0.0\n");
    return EXIT_SUCCESS;
  }

  if (args.daemon) {
    if (!btc_ps_daemon()) {
      fprintf(stderr, "Could not daemonize process.\n");
      return EXIT_FAILURE;
    }
  }

  btc_net_startup();

  node = btc_node_create(args.network);
  map_size = (uint64_t)args.map_size << 30;

  if (!btc_node_open(node, args.prefix, map_size)) {
    btc_node_destroy(node);
    btc_net_cleanup();
    return EXIT_FAILURE;
  }

  btc_node_start(node);

  btc_net_cleanup();

  return EXIT_SUCCESS;
}
