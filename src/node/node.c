/*!
 * main.c - main entry point for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <io/core.h>
#include <io/loop.h>

#include <node/addrman.h>
#include <node/chain.h>
#include <node/logger.h>
#include <node/mempool.h>
#include <node/miner.h>
#include <node/node.h>
#include <node/pool.h>
#include <node/rpc.h>
#include <node/timedata.h>

#include <satoshi/block.h>
#include <satoshi/coins.h>
#include <satoshi/consensus.h>
#include <satoshi/crypto/hash.h>
#include <satoshi/entry.h>
#include <satoshi/header.h>
#include <satoshi/net.h>
#include <satoshi/netaddr.h>
#include <satoshi/netmsg.h>
#include <satoshi/network.h>
#include <satoshi/script.h>
#include <satoshi/tx.h>
#include <satoshi/util.h>
#include <satoshi/vector.h>

#include "../internal.h"

/*
 * Callbacks
 */

static void
on_connect(const btc_entry_t *entry,
           const btc_block_t *block,
           const btc_view_t *view,
           void *arg);

static void
on_disconnect(const btc_entry_t *entry,
              const btc_block_t *block,
              const btc_view_t *view,
              void *arg);


static void
on_reorganize(const btc_entry_t *old, const btc_entry_t *new_, void *arg);


static void
on_tx(const btc_mpentry_t *entry, const btc_view_t *view, void *arg);

/*
 * Node
 */

btc_node_t *
btc_node_create(const btc_network_t *network) {
  btc_node_t *node = (btc_node_t *)btc_malloc(sizeof(btc_node_t));

  memset(node, 0, sizeof(*node));

  node->network = network;
  node->loop = btc_loop_create();
  node->logger = btc_logger_create();
  node->timedata = btc_timedata_create();
  node->chain = btc_chain_create(network);
  node->mempool = btc_mempool_create(network, node->chain);
  node->miner = btc_miner_create(network, node->loop, node->chain, node->mempool);
  node->pool = btc_pool_create(network, node->loop, node->chain, node->mempool);
  node->rpc = btc_rpc_create(node);

  btc_chain_set_logger(node->chain, node->logger);
  btc_mempool_set_logger(node->mempool, node->logger);
  btc_miner_set_logger(node->miner, node->logger);
  btc_pool_set_logger(node->pool, node->logger);

  btc_chain_set_timedata(node->chain, node->timedata);
  btc_mempool_set_timedata(node->mempool, node->timedata);
  btc_miner_set_timedata(node->miner, node->timedata);
  btc_pool_set_timedata(node->pool, node->timedata);

  btc_chain_set_context(node->chain, node);
  btc_chain_on_connect(node->chain, on_connect);
  btc_chain_on_disconnect(node->chain, on_disconnect);
  btc_chain_on_reorganize(node->chain, on_reorganize);

  btc_mempool_set_context(node->mempool, node);
  btc_mempool_on_tx(node->mempool, on_tx);

  return node;
}

void
btc_node_destroy(btc_node_t *node) {
  btc_loop_destroy(node->loop);
  btc_logger_destroy(node->logger);
  btc_timedata_destroy(node->timedata);
  btc_chain_destroy(node->chain);
  btc_mempool_destroy(node->mempool);
  btc_miner_destroy(node->miner);
  btc_pool_destroy(node->pool);
  btc_rpc_destroy(node->rpc);
  btc_free(node);
}

static void
btc_node_log(btc_node_t *node, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  btc_logger_write(node->logger, "node", fmt, ap);
  va_end(ap);
}

int
btc_node_open(btc_node_t *node, const char *prefix, unsigned int flags) {
  char path[BTC_PATH_MAX];
  char file[BTC_PATH_MAX];

  btc_node_log(node, "Opening node.");

  if (!btc_path_resolve(path, sizeof(path), prefix, 0))
    return 0;

  if (!btc_fs_mkdirp(path, 0755))
    return 0;

  if (!btc_path_join(file, sizeof(file), path, "debug.log", 0))
    return 0;

  if (!btc_logger_open(node->logger, file))
    return 0;

  btc_node_log(node, "Opening node.");

  if (!btc_chain_open(node->chain, path, flags))
    goto fail1;

  if (!btc_mempool_open(node->mempool, path, flags))
    goto fail2;

  if (!btc_miner_open(node->miner, flags))
    goto fail3;

  if (!btc_pool_open(node->pool, path, flags))
    goto fail4;

  if (!btc_rpc_open(node->rpc, flags))
    goto fail5;

  return 1;
fail5:
  btc_pool_close(node->pool);
fail4:
  btc_miner_close(node->miner);
fail3:
  btc_mempool_close(node->mempool);
fail2:
  btc_chain_close(node->chain);
fail1:
  btc_logger_close(node->logger);
  return 0;
}

void
btc_node_close(btc_node_t *node) {
  btc_node_log(node, "Closing node.");

  btc_rpc_close(node->rpc);
  btc_pool_close(node->pool);
  btc_miner_close(node->miner);
  btc_mempool_close(node->mempool);
  btc_chain_close(node->chain);
  btc_logger_close(node->logger);
}

void
btc_node_start(btc_node_t *node) {
  btc_loop_start(node->loop);
}

void
btc_node_stop(btc_node_t *node) {
  btc_loop_stop(node->loop);
}

/*
 * Event Handling
 */

static void
on_connect(const btc_entry_t *entry,
           const btc_block_t *block,
           const btc_view_t *view,
           void *arg) {
  btc_node_t *node = (btc_node_t *)arg;

  (void)view;

  btc_mempool_add_block(node->mempool, entry, block);
}

static void
on_disconnect(const btc_entry_t *entry,
              const btc_block_t *block,
              const btc_view_t *view,
              void *arg) {
  btc_node_t *node = (btc_node_t *)arg;

  (void)view;

  btc_mempool_remove_block(node->mempool, entry, block);
}

static void
on_reorganize(const btc_entry_t *old, const btc_entry_t *new_, void *arg) {
  btc_node_t *node = (btc_node_t *)arg;

  (void)old;
  (void)new_;

  btc_mempool_handle_reorg(node->mempool);
}

static void
on_tx(const btc_mpentry_t *entry, const btc_view_t *view, void *arg) {
  btc_node_t *node = (btc_node_t *)arg;

  (void)node;
  (void)entry;
  (void)view;
}
