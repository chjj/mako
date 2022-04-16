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
#include <base/logger.h>
#include <node/node.h>
#include <node/pool.h>
#include <node/rpc.h>

#include <base/config.h>
#include <mako/netaddr.h>
#include <mako/util.h>

#include "../internal.h"

/*
 * Arguments
 */

static const char *node_args[] = {
  "-?",
  "-bantime=",
  "-bind=",
  "-blocksonly=",
  "-chain=",
  "-checkpoints=",
  "-compactblocks=",
  "-conf=",
  "-connect=",
  "-daemon=",
  "-datadir=",
  "-dbcache=",
  "-disablewallet=",
  "-discover=",
  "-externalip=",
  "-listen=",
  "-loglevel=",
  "-maxconnections=",
  "-maxinbound=",
  "-maxoutbound=",
  "-networkactive=",
  "-onion=",
  "-onlynet=",
  "-par=",
  "-peerblockfilters=",
  "-peerbloomfilters=",
  "-port=",
  "-proxy=",
  "-prune=",
  "-rpcbind=",
  "-rpcconnect=",
  "-rpcpassword=",
  "-rpcport=",
  "-rpcuser=",
  "-testnet",
  "-upnp=",
  "-version"
};

/*
 * Config
 */

static btc_conf_t *
get_config(int argc, char **argv) {
  char prefix[BTC_PATH_MAX];
  btc_conf_t *conf;

  if (!btc_sys_datadir(prefix, sizeof(prefix), "mako")) {
    fprintf(stderr, "Could not find suitable datadir.\n");
    return NULL;
  }

  conf = btc_conf_create(argc, argv, prefix, 0);

  /* Absolute-ify path before we daemonize and call chdir("/"). */
  if (!btc_path_absolutify(conf->prefix, sizeof(conf->prefix))) {
    fprintf(stderr, "Path for datadir is too long!\n");
    btc_conf_destroy(conf);
    return NULL;
  }

  return conf;
}

static void
set_config(btc_node_t *node, const btc_conf_t *conf) {
  size_t i;

  btc_logger_set_level(node->logger, conf->level);

  btc_chain_set_threads(node->chain, conf->workers);
  btc_chain_set_cache(node->chain, (size_t)conf->cache_size << 20);

  btc_pool_set_port(node->pool, conf->port);

  for (i = 0; i < conf->bind.length; i++)
    btc_pool_set_bind(node->pool, conf->bind.items[i]);

  for (i = 0; i < conf->external.length; i++)
    btc_pool_set_external(node->pool, conf->external.items[i]);

  for (i = 0; i < conf->connect.length; i++)
    btc_pool_set_connect(node->pool, conf->connect.items[i]);

  btc_pool_set_proxy(node->pool, &conf->proxy);
  btc_pool_set_maxinbound(node->pool, conf->max_inbound);
  btc_pool_set_maxoutbound(node->pool, conf->max_outbound);
  btc_pool_set_bantime(node->pool, conf->ban_time);
  btc_pool_set_onlynet(node->pool, conf->only_net);

  btc_rpc_set_port(node->rpc, conf->rpc_port);

  for (i = 0; i < conf->rpc_bind.length; i++)
    btc_rpc_set_bind(node->rpc, conf->rpc_bind.items[i]);

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

  if (conf->connect.length > 0 || conf->no_connect)
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

static int
btc_main(const btc_conf_t *conf) {
  btc_node_t *node;

  if (conf->help) {
    puts("Usage: makod [options]");
    return 1;
  }

  if (conf->version) {
    puts("0.0.0");
    return 1;
  }

  if (conf->daemon) {
    if (!btc_ps_daemon()) {
      fprintf(stderr, "Could not daemonize process.\n");
      return 0;
    }
  }

  {
    int needed = conf->max_inbound + conf->max_outbound + 1000 + 125 + 200;

    if (needed < 8192)
      needed = 8192;

    btc_ps_fdlimit(needed);
  }

  btc_net_startup();

  node = btc_node_create(conf->network);

  set_config(node, conf);

  if (!btc_node_open(node, conf->prefix, get_node_flags(conf))) {
    btc_node_destroy(node);
    btc_net_cleanup();
    return 0;
  }

  btc_ps_onterm(on_sigterm, node);

  btc_node_start(node);

  btc_node_close(node);
  btc_node_destroy(node);

  btc_net_cleanup();

  return 1;
}

int
main(int argc, char **argv) {
  btc_conf_t *conf;
  int ok;

  if (argc > 1 && strcmp(argv[1], "_complete") == 0) {
    const char *word = argc > 2 ? argv[argc - 1] : "";
    size_t i;

    for (i = 0; i < lengthof(node_args); i++) {
      if (btc_starts_with(node_args[i], word))
        puts(node_args[i]);
    }

    return EXIT_SUCCESS;
  }

  conf = get_config(argc, argv);

  if (conf == NULL)
    return EXIT_FAILURE;

  ok = btc_main(conf);

  btc_conf_destroy(conf);

  return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
