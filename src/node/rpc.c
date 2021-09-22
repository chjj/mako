/*!
 * rpc.c - rpc for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

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

#include "../map.h"
#include "../internal.h"

/*
 * RPC
 */

struct btc_rpc_s {
  btc_node_t *node;
  const btc_network_t *network;
  btc_loop_t *loop;
  btc_logger_t *logger;
  const btc_timedata_t *timedata;
  btc_chain_t *chain;
  btc_mempool_t *mempool;
  btc_miner_t *miner;
  btc_pool_t *pool;
};

struct btc_rpc_s *
btc_rpc_create(btc_node_t *node) {
  struct btc_rpc_s *rpc =
    (struct btc_rpc_s *)btc_malloc(sizeof(struct btc_rpc_s));

  memset(rpc, 0, sizeof(*rpc));

  rpc->node = node;
  rpc->network = node->network;
  rpc->loop = node->loop;
  rpc->logger = node->logger;
  rpc->timedata = node->timedata;
  rpc->chain = node->chain;
  rpc->mempool = node->mempool;
  rpc->miner = node->miner;
  rpc->pool = node->pool;

  return rpc;
}

void
btc_rpc_destroy(struct btc_rpc_s *rpc) {
  btc_free(rpc);
}

static void
btc_rpc_log(struct btc_rpc_s *rpc, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  btc_logger_write(rpc->logger, "rpc", fmt, ap);
  va_end(ap);
}

int
btc_rpc_open(struct btc_rpc_s *rpc) {
  btc_rpc_log(rpc, "Opening rpc.");
  return 1;
}

void
btc_rpc_close(struct btc_rpc_s *rpc) {
  (void)rpc;
}
