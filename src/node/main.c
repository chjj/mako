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

/*
 * Config
 */

static int
get_config(btc_conf_t *args, int argc, char **argv) {
  char prefix[700];
  btc_conf_t conf;

  if (!btc_sys_datadir(prefix, sizeof(prefix), "satoshi")) {
    fprintf(stderr, "Could not find suitable datadir.\n");
    return 0;
  }

  btc_conf_parse(args, argv, argc, prefix, 0);

  if (!args->help && !args->version) {
    btc_conf_read(&conf, args->config);
    btc_conf_merge(args, &conf);
  }

  btc_conf_finalize(args, prefix);

  if (!btc_path_absolute(args->prefix, sizeof(args->prefix))) {
    fprintf(stderr, "Path for datadir is too long!\n");
    return 0;
  }

  return 1;
}

/*
 * Signal Handling
 */

static void
on_sigterm(void *arg) {
  btc_node_stop((btc_node_t *)arg);
}

/*
 * Main
 */

int
main(int argc, char **argv) {
  uint64_t map_size;
  btc_node_t *node;
  btc_conf_t args;

  if (!get_config(&args, argc, argv))
    return EXIT_FAILURE;

  if (args.help) {
    puts("Usage: satoshid [options]");
    return EXIT_SUCCESS;
  }

  if (args.version) {
    puts("0.0.0");
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

  btc_ps_onterm(on_sigterm, node);

  btc_node_start(node);

  btc_node_close(node);
  btc_node_destroy(node);

  btc_net_cleanup();

  return EXIT_SUCCESS;
}
