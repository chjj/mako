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
#include <satoshi/map.h>
#include <satoshi/network.h>
#include <satoshi/policy.h>
#include <satoshi/script.h>
#include <satoshi/tx.h>
#include <satoshi/util.h>
#include <satoshi/vector.h>

#include "../impl.h"
#include "../internal.h"

/*
 * Mempool
 */

struct btc_mempool_s {
  const btc_network_t *network;
  btc_logger_t *logger;
  const btc_timedata_t *timedata;
  btc_hashmap_t *map;
  btc_chain_t *chain;
  btc_verify_error_t error;
  btc_mempool_tx_cb *on_tx;
  btc_mempool_badorphan_cb *on_badorphan;
  void *arg;
};

struct btc_mempool_s *
btc_mempool_create(const btc_network_t *network, btc_chain_t *chain) {
  struct btc_mempool_s *mp =
    (struct btc_mempool_s *)btc_malloc(sizeof(struct btc_mempool_s));

  memset(mp, 0, sizeof(*mp));

  mp->network = network;
  mp->logger = NULL;
  mp->timedata = NULL;
  mp->map = btc_hashmap_create();
  mp->chain = chain;
  mp->on_tx = NULL;
  mp->on_badorphan = NULL;
  mp->arg = NULL;

  return mp;
}

void
btc_mempool_destroy(struct btc_mempool_s *mp) {
  btc_hashmapiter_t iter;

  btc_hashmap_iterate(&iter, mp->map);

  while (btc_hashmap_next(&iter))
    btc_mpentry_destroy(iter.val);

  btc_hashmap_destroy(mp->map);
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

void
btc_mempool_on_tx(struct btc_mempool_s *mp, btc_mempool_tx_cb *handler) {
  mp->on_tx = handler;
}

void
btc_mempool_on_badorphan(struct btc_mempool_s *mp,
                         btc_mempool_badorphan_cb *handler) {
  mp->on_badorphan = handler;
}

void
btc_mempool_set_context(struct btc_mempool_s *mp, void *arg) {
  mp->arg = arg;
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

BTC_UNUSED static int
btc_chain_throw(struct btc_mempool_s *mp,
                const uint8_t *hash,
                const char *code,
                const char *reason,
                int score,
                int malleated) {
  btc_hash_copy(mp->error.hash, hash);

  mp->error.code = code;
  mp->error.reason = reason;
  mp->error.score = score;
  mp->error.malleated = malleated;

  btc_mempool_log(mp, "Verification error: %s "
                      "(code=%s score=%d hash=%H)",
                  reason, code, score, hash);

  return 0;
}

const btc_verify_error_t *
btc_mempool_error(struct btc_mempool_s *mp) {
  return &mp->error;
}

void
btc_mempool_add_block(struct btc_mempool_s *mp,
                      const btc_entry_t *entry,
                      const btc_block_t *block) {
  (void)mp;
  (void)entry;
  (void)block;
}

void
btc_mempool_remove_block(struct btc_mempool_s *mp,
                         const btc_entry_t *entry,
                         const btc_block_t *block) {
  (void)mp;
  (void)entry;
  (void)block;
}

void
btc_mempool_handle_reorg(struct btc_mempool_s *mp) {
  (void)mp;
}

int
btc_mempool_add(struct btc_mempool_s *mp,
                btc_vector_t *missing,
                const btc_tx_t *tx,
                unsigned int id) {
  btc_mpentry_t *entry = btc_mpentry_create();

  (void)missing;
  (void)id;

  btc_mpentry_set(entry, tx);

  entry->height = btc_chain_height(mp->chain);
  entry->time = btc_timedata_now(mp->timedata);

  if (!btc_hashmap_put(mp->map, entry->hash, entry)) {
    btc_mpentry_destroy(entry);
    return 0;
  }

  return 1;
}

int
btc_mempool_has(struct btc_mempool_s *mp, const uint8_t *hash) {
  return btc_hashmap_has(mp->map, hash);
}

const btc_mpentry_t *
btc_mempool_get(struct btc_mempool_s *mp, const uint8_t *hash) {
  return btc_hashmap_get(mp->map, hash);
}

int
btc_mempool_has_reject(struct btc_mempool_s *mp, const uint8_t *hash) {
  (void)mp;
  (void)hash;
  return 0;
}

void
btc_mempool_iterate(btc_mpiter_t *iter, struct btc_mempool_s *mp) {
  btc_hashmap_iterate(iter, mp->map);
}

int
btc_mempool_next(const btc_mpentry_t **entry, btc_mpiter_t *iter) {
  if (btc_hashmap_next(iter)) {
    *entry = iter->val;
    return 1;
  }
  return 0;
}

/**
 * Mempool Entry
 */

DEFINE_SERIALIZABLE_OBJECT(btc_mpentry, SCOPE_EXTERN)

void
btc_mpentry_init(btc_mpentry_t *entry) {
  btc_tx_init(&entry->tx);

  memset(entry->hash, 0, 32);
  memset(entry->whash, 0, 32);

  entry->height = -1;
  entry->size = 0;
  entry->sigops = 0;
  entry->priority = 0;
  entry->fee = 0;
  entry->delta_fee = 0;
  entry->time = 0;
  entry->value = 0;
  entry->coinbase = 0;
  entry->dependencies = 0;
  entry->desc_fee = 0;
  entry->desc_size = 0;
}

void
btc_mpentry_clear(btc_mpentry_t *entry) {
  btc_tx_clear(&entry->tx);
}

void
btc_mpentry_copy(btc_mpentry_t *z, const btc_mpentry_t *x) {
  btc_tx_copy(&z->tx, &x->tx);

  memcpy(z->hash, x->hash, 32);
  memcpy(z->whash, x->whash, 32);

  z->height = x->height;
  z->size = x->size;
  z->sigops = x->sigops;
  z->priority = x->priority;
  z->fee = x->fee;
  z->delta_fee = x->delta_fee;
  z->time = x->time;
  z->value = x->value;
  z->coinbase = x->coinbase;
  z->dependencies = x->dependencies;
  z->desc_fee = x->desc_fee;
  z->desc_size = x->desc_size;
}

void
btc_mpentry_set(btc_mpentry_t *z, const btc_tx_t *tx) {
  btc_tx_copy(&z->tx, tx);
  btc_tx_txid(z->hash, tx);
  btc_tx_wtxid(z->whash, tx);
}

size_t
btc_mpentry_size(const btc_mpentry_t *x) {
  return btc_tx_size(&x->tx) + 46;
}

uint8_t *
btc_mpentry_write(uint8_t *zp, const btc_mpentry_t *x) {
  zp = btc_tx_write(zp, &x->tx);
  zp = btc_int32_write(zp, x->height);
  zp = btc_uint32_write(zp, x->size);
  zp = btc_uint32_write(zp, x->sigops);
  zp = btc_double_write(zp, x->priority);
  zp = btc_int64_write(zp, x->fee);
  zp = btc_int64_write(zp, x->time);
  zp = btc_int64_write(zp, x->value);
  zp = btc_uint8_write(zp, x->coinbase);
  zp = btc_uint8_write(zp, x->dependencies);
  return zp;
}

int
btc_mpentry_read(btc_mpentry_t *z, const uint8_t **xp, size_t *xn) {
  if (!btc_tx_read(&z->tx, xp, xn))
    return 0;

  if (!btc_int32_read(&z->height, xp, xn))
    return 0;

  if (!btc_uint32_read(&z->size, xp, xn))
    return 0;

  if (!btc_uint32_read(&z->sigops, xp, xn))
    return 0;

  if (!btc_double_read(&z->priority, xp, xn))
    return 0;

  if (!btc_int64_read(&z->fee, xp, xn))
    return 0;

  if (!btc_int64_read(&z->time, xp, xn))
    return 0;

  if (!btc_int64_read(&z->value, xp, xn))
    return 0;

  if (!btc_uint8_read(&z->coinbase, xp, xn))
    return 0;

  if (!btc_uint8_read(&z->dependencies, xp, xn))
    return 0;

  btc_tx_txid(z->hash, &z->tx);
  btc_tx_wtxid(z->whash, &z->tx);

  return 1;
}
