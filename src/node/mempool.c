/*!
 * mempool.c - mempool for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <node/chain.h>
#include <node/logger.h>
#include <node/mempool.h>
#include <node/timedata.h>

#include <satoshi/block.h>
#include <satoshi/coins.h>
#include <satoshi/consensus.h>
#include <satoshi/crypto/hash.h>
#include <satoshi/crypto/rand.h>
#include <satoshi/entry.h>
#include <satoshi/header.h>
#include <satoshi/network.h>
#include <satoshi/policy.h>
#include <satoshi/script.h>
#include <satoshi/tx.h>
#include <satoshi/util.h>
#include <satoshi/vector.h>

#include "../map.h"
#include "../internal.h"

/*
 * Mempool
 */

struct btc_mempool_s {
  const btc_network_t *network;
  btc_logger_t *logger;
  const btc_timedata_t *timedata;
  btc_chain_t *chain;
};

struct btc_mempool_s *
btc_mempool_create(const btc_network_t *network, btc_chain_t *chain) {
  struct btc_mempool_s *mp =
    (struct btc_mempool_s *)btc_malloc(sizeof(struct btc_mempool_s));

  memset(mp, 0, sizeof(*mp));

  mp->network = network;
  mp->logger = NULL;
  mp->timedata = NULL;
  mp->chain = chain;

  return mp;
}

void
btc_mempool_destroy(struct btc_mempool_s *mp) {
  btc_free(mp);
}

void
btc_mempool_set_logger(struct btc_mempool_s *mp, btc_logger_t *logger) {
  mp->logger = logger;
}

void
btc_mempool_set_timedata(struct btc_mempool_s *mp, const btc_timedata_t *td) {
  mp->timedata = td;
}

static void
btc_mempool_log(struct btc_mempool_s *mp, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  btc_logger_write(mp->logger, "mempool", fmt, ap);
  va_end(ap);
}

int
btc_mempool_open(struct btc_mempool_s *mp) {
  btc_mempool_log(mp, "Opening mempool.");
  return 1;
}

void
btc_mempool_close(struct btc_mempool_s *mp) {
  (void)mp;
}

BTC_UNUSED static int64_t
btc_mempool_now(struct btc_mempool_s *mp) {
  if (mp->timedata == NULL)
    return btc_now();

  return btc_timedata_now(mp->timedata);
}
