/*!
 * main.c - main entry point for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <io/core.h>

#include <node/chain.h>
#include <node/node.h>
#include <node/pool.h>
#include <node/rpc.h>

#include <mako/config.h>
#include <mako/netaddr.h>

/*
 * Config
 */

static int
get_config(btc_conf_t *args, int argc, char **argv) {
  char prefix[BTC_PATH_MAX];

  if (!btc_sys_datadir(prefix, sizeof(prefix), "mako")) {
    fprintf(stderr, "Could not find suitable datadir.\n");
    return 0;
  }

  btc_conf_init(args, argc, argv, prefix, 0);

  /* Absolute-ify path before we daemonize and call chdir("/"). */
  if (!btc_path_absolute(args->prefix, sizeof(args->prefix))) {
    fprintf(stderr, "Path for datadir is too long!\n");
    return 0;
  }

  return 1;
}

static void
set_config(btc_node_t *node, const btc_conf_t *conf) {
  btc_chain_set_threads(node->chain, conf->workers);

  btc_pool_set_port(node->pool, conf->port);
  btc_pool_set_bind(node->pool, &conf->bind);
  btc_pool_set_external(node->pool, &conf->external);
  btc_pool_set_connect(node->pool, &conf->connect);
  btc_pool_set_proxy(node->pool, &conf->proxy);
  btc_pool_set_maxoutbound(node->pool, conf->max_outbound);
  btc_pool_set_maxinbound(node->pool, conf->max_inbound);
  btc_pool_set_bantime(node->pool, conf->ban_time);
  btc_pool_set_onlynet(node->pool, conf->only_net);

  btc_rpc_set_bind(node->rpc, &conf->rpc_bind);
  btc_rpc_set_credentials(node->rpc, conf->rpc_user, conf->rpc_pass);
}

static unsigned int
get_node_flags(const btc_conf_t *conf) {
  unsigned int flags = 0;

  if (conf->checkpoints)
    flags |= BTC_CHAIN_CHECKPOINTS;

  if (conf->prune)
    flags |= BTC_CHAIN_PRUNE;

  if (conf->listen)
    flags |= BTC_POOL_LISTEN;

  if (conf->checkpoints)
    flags |= BTC_POOL_CHECKPOINTS;

  if (conf->no_connect)
    flags |= BTC_POOL_NOCONNECT;

  if (!btc_netaddr_is_null(&conf->connect))
    flags |= BTC_POOL_CONNECT;

  if (!btc_netaddr_is_null(&conf->proxy))
    flags |= BTC_POOL_PROXY;

  if (conf->discover)
    flags |= BTC_POOL_DISCOVER;

  if (conf->upnp)
    flags |= BTC_POOL_UPNP;

  if (conf->onion)
    flags |= BTC_POOL_ONION;

  if (conf->blocks_only)
    flags |= BTC_POOL_BLOCKSONLY;

  if (conf->bip37)
    flags |= BTC_POOL_BIP37;

  if (conf->bip152)
    flags |= BTC_POOL_BIP152;

  if (conf->bip157)
    flags |= BTC_POOL_BIP157;

  return flags;
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
  btc_node_t *node;
  btc_conf_t args;

  if (!get_config(&args, argc, argv))
    return EXIT_FAILURE;

  if (args.help) {
    puts("Usage: makod [options]");
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

  set_config(node, &args);

  if (!btc_node_open(node, args.prefix, get_node_flags(&args))) {
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
