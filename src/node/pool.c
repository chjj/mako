/*!
 * pool.c - p2p pool for libsatoshi
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
#include <node/pool.h>
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
 * Pool
 */

struct btc_pool_s {
  const btc_network_t *network;
  btc_loop_t *loop;
  btc_logger_t *logger;
  const btc_timedata_t *timedata;
  btc_addrman_t *addrman;
  btc_chain_t *chain;
  btc_mempool_t *mempool;
};

struct btc_pool_s *
btc_pool_create(const btc_network_t *network,
                btc_loop_t *loop,
                btc_chain_t *chain,
                btc_mempool_t *mempool) {
  struct btc_pool_s *pool =
    (struct btc_pool_s *)btc_malloc(sizeof(struct btc_pool_s));

  memset(pool, 0, sizeof(*pool));

  pool->network = network;
  pool->loop = loop;
  pool->logger = NULL;
  pool->timedata = NULL;
  pool->addrman = btc_addrman_create(network);
  pool->chain = chain;
  pool->mempool = mempool;

  return pool;
}

void
btc_pool_destroy(struct btc_pool_s *pool) {
  btc_addrman_destroy(pool->addrman);
  btc_free(pool);
}

void
btc_pool_set_logger(struct btc_pool_s *pool, btc_logger_t *logger) {
  pool->logger = logger;
}

void
btc_pool_set_timedata(struct btc_pool_s *pool, const btc_timedata_t *td) {
  pool->timedata = td;
}

static void
btc_pool_log(struct btc_pool_s *pool, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  btc_logger_write(pool->logger, "pool", fmt, ap);
  va_end(ap);
}

int
btc_pool_open(struct btc_pool_s *pool) {
  btc_pool_log(pool, "Opening pool.");

  if (!btc_addrman_open(pool->addrman))
    return 0;

  return 1;
}

void
btc_pool_close(struct btc_pool_s *pool) {
  btc_addrman_close(pool->addrman);
}

BTC_UNUSED static int64_t
btc_pool_now(struct btc_pool_s *pool) {
  if (pool->timedata == NULL)
    return btc_now();

  return btc_timedata_now(pool->timedata);
}
