/*!
 * miner.c - miner for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <io/loop.h>

#include <node/chain.h>
#include <node/logger.h>
#include <node/mempool.h>
#include <node/miner.h>
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
 * Miner
 */

struct btc_miner_s {
  const btc_network_t *network;
  btc_loop_t *loop;
  btc_logger_t *logger;
  const btc_timedata_t *timedata;
  btc_chain_t *chain;
  btc_mempool_t *mempool;
};

struct btc_miner_s *
btc_miner_create(const btc_network_t *network,
                 btc_loop_t *loop,
                 btc_chain_t *chain,
                 btc_mempool_t *mempool) {
  struct btc_miner_s *miner =
    (struct btc_miner_s *)btc_malloc(sizeof(struct btc_miner_s));

  memset(miner, 0, sizeof(*miner));

  miner->network = network;
  miner->loop = loop;
  miner->logger = NULL;
  miner->timedata = NULL;
  miner->chain = chain;
  miner->mempool = mempool;

  return miner;
}

void
btc_miner_destroy(struct btc_miner_s *miner) {
  btc_free(miner);
}

void
btc_miner_set_logger(struct btc_miner_s *miner, btc_logger_t *logger) {
  miner->logger = logger;
}

void
btc_miner_set_timedata(struct btc_miner_s *miner, const btc_timedata_t *td) {
  miner->timedata = td;
}

static void
btc_miner_log(struct btc_miner_s *miner, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  btc_logger_write(miner->logger, "miner", fmt, ap);
  va_end(ap);
}

int
btc_miner_open(struct btc_miner_s *miner) {
  btc_miner_log(miner, "Opening miner.");
  return 1;
}

void
btc_miner_close(struct btc_miner_s *miner) {
  (void)miner;
}
