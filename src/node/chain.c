/*!
 * chain.c - chain for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <io/core.h>
#include <io/workers.h>

#include <node/chain.h>
#include <node/chaindb.h>
#include <base/logger.h>
#include <base/timedata.h>

#include <mako/block.h>
#include <mako/coins.h>
#include <mako/consensus.h>
#include <mako/crypto/hash.h>
#include <mako/entry.h>
#include <mako/header.h>
#include <mako/list.h>
#include <mako/map.h>
#include <mako/mpi.h>
#include <mako/netmsg.h>
#include <mako/network.h>
#include <mako/script.h>
#include <mako/tx.h>
#include <mako/util.h>
#include <mako/vector.h>

#include "../impl.h"
#include "../internal.h"

/*
 * Deployment State
 */

static void
btc_deployment_state_init(btc_deployment_state_t *state) {
  memset(state, 0, sizeof(*state));

  state->flags = BTC_SCRIPT_MANDATORY_VERIFY_FLAGS;
  state->flags &= ~BTC_SCRIPT_VERIFY_P2SH;
  state->lock_flags = BTC_MANDATORY_LOCKTIME_FLAGS;
  state->bip34 = 0;
}

/*
 * Orphan Block
 */

typedef struct btc_orphan_s {
  uint8_t hash[32];
  btc_block_t *block;
  unsigned int id;
  int64_t time;
} btc_orphan_t;

DEFINE_OBJECT(btc_orphan, SCOPE_STATIC)

static void
btc_orphan_init(btc_orphan_t *orphan) {
  memset(orphan, 0, sizeof(*orphan));
}

static void
btc_orphan_clear(btc_orphan_t *orphan) {
  if (orphan->block != NULL)
    btc_block_destroy(orphan->block);

  orphan->block = NULL;
}

static void
btc_orphan_copy(btc_orphan_t *z, const btc_orphan_t *x) {
  *z = *x;
}

/*
 * TX Checker
 */

typedef struct btc_txwork_s {
  const btc_tx_t *tx;
  const btc_view_t *view;
  unsigned int flags;
  int result;
  struct btc_txwork_s *next;
} btc_txwork_t;

typedef struct btc_checker_s {
  btc_workers_t *pool;
  btc_txwork_t *head;
  btc_txwork_t *tail;
  btc_workq_t batch;
  size_t length;
} btc_checker_t;

static void
btc_checker_init(btc_checker_t *checker, btc_workers_t *pool) {
  checker->pool = pool;
  btc_queue_init(checker);
  btc_workq_init(&checker->batch);
}

static void
btc_checker_work(void *arg) {
  btc_txwork_t *work = arg;

  work->result = btc_tx_verify(work->tx, work->view, work->flags);
}

static void
btc_checker_push(btc_checker_t *checker,
                 const btc_tx_t *tx,
                 const btc_view_t *view,
                 unsigned int flags) {
  btc_txwork_t *work = btc_malloc(sizeof(btc_txwork_t));

  work->tx = tx;
  work->view = view;
  work->flags = flags;
  work->result = 0;
  work->next = NULL;

  btc_queue_push(checker, work);
  btc_workq_push(&checker->batch, btc_checker_work, work);
}

static int
btc_checker_verify(btc_checker_t *checker) {
  btc_txwork_t *work, *next;
  int ret = 1;

  btc_workers_batch(checker->pool, &checker->batch);
  btc_workers_wait(checker->pool);

  for (work = checker->head; work != NULL; work = next) {
    next = work->next;
    ret &= work->result;
    btc_free(work);
  }

  btc_queue_init(checker);

  return ret;
}

/*
 * State Cache
 */

typedef struct btc_statecache_s {
  btc_hashtab_t *bits[32];
} btc_statecache_t;

static void
btc_statecache_init(btc_statecache_t *cache, const btc_network_t *network) {
  const btc_deployment_t *deploy;
  size_t i;

  for (i = 0; i < 32; i++)
    cache->bits[i] = NULL;

  for (i = 0; i < network->deployments.length; i++) {
    deploy = &network->deployments.items[i];

    CHECK(cache->bits[deploy->bit] == NULL);

    cache->bits[deploy->bit] = btc_hashtab_create();
  }
}

static void
btc_statecache_clear(btc_statecache_t *cache) {
  int i;

  for (i = 0; i < 32; i++) {
    if (cache->bits[i] != NULL)
      btc_hashtab_destroy(cache->bits[i]);

    cache->bits[i] = NULL;
  }
}

static void
btc_statecache_set(btc_statecache_t *cache,
                   int bit,
                   const btc_entry_t *entry,
                   int state) {
  btc_hashtab_t *map = cache->bits[bit];

  CHECK(map != NULL);

  btc_hashtab_put(map, entry->hash, state);
}

static int
btc_statecache_get(btc_statecache_t *cache, int bit, const btc_entry_t *entry) {
  btc_hashtab_t *map = cache->bits[bit];

  CHECK(map != NULL);

  return btc_hashtab_get(map, entry->hash);
}

/*
 * Chain
 */

struct btc_chain_s {
  const btc_network_t *network;
  btc_logger_t *logger;
  btc_chaindb_t *db;
  const btc_timedata_t *timedata;
  btc_workers_t *workers;
  btc_hashset_t invalid;
  btc_hashmap_t orphan_map;
  btc_hashmap_t orphan_prev;
  btc_statecache_t cache;
  btc_entry_t *tip;
  int32_t height;
  mpz_t limit;
  btc_deployment_state_t state;
  btc_verify_error_t error;
  int synced;
  unsigned int flags;
  int threads;
  btc_chain_block_cb *on_block;
  btc_chain_connect_cb *on_connect;
  btc_chain_connect_cb *on_disconnect;
  btc_chain_reorganize_cb *on_reorganize;
  btc_chain_badorphan_cb *on_badorphan;
  void *arg;
};

BTC_DEFINE_LOGGER(btc_log, btc_chain_t, "chain")

btc_chain_t *
btc_chain_create(const btc_network_t *network) {
  btc_chain_t *chain = btc_malloc(sizeof(btc_chain_t));

  memset(chain, 0, sizeof(*chain));

  chain->network = network;
  chain->logger = NULL;
  chain->db = btc_chaindb_create(network);
  chain->timedata = NULL;
  btc_hashset_init(&chain->invalid);
  btc_hashmap_init(&chain->orphan_map);
  btc_hashmap_init(&chain->orphan_prev);
  btc_statecache_init(&chain->cache, network);
  chain->tip = NULL;
  chain->height = -1;

  mpz_init_import(chain->limit, network->pow.limit, 32, -1);

  btc_deployment_state_init(&chain->state);

  chain->flags = BTC_CHAIN_DEFAULT_FLAGS;

  btc_chain_set_threads(chain, 0);

  return chain;
}

void
btc_chain_destroy(btc_chain_t *chain) {
  btc_mapiter_t it;

  btc_map_each(&chain->invalid, it)
    btc_free(chain->invalid.keys[it]);

  btc_map_each(&chain->orphan_map, it)
    btc_orphan_destroy(chain->orphan_map.vals[it]);

  btc_hashset_clear(&chain->invalid);
  btc_hashmap_clear(&chain->orphan_map);
  btc_hashmap_clear(&chain->orphan_prev);
  btc_statecache_clear(&chain->cache);

  btc_chaindb_destroy(chain->db);

  mpz_clear(chain->limit);

  btc_free(chain);
}

void
btc_chain_set_logger(btc_chain_t *chain, btc_logger_t *logger) {
  chain->logger = logger;
}

void
btc_chain_set_timedata(btc_chain_t *chain, const btc_timedata_t *td) {
  chain->timedata = td;
}

void
btc_chain_set_threads(btc_chain_t *chain, int threads) {
  if (threads <= 0) {
    int num = btc_sys_numcpu();

    if (num < 1)
      num = 1;

    threads += num;
  }

  if (threads <= 1)
    threads = 0;
  else if (threads > 16)
    threads = 16;

  chain->threads = threads;
}

void
btc_chain_set_cache(btc_chain_t *chain, size_t cache_size) {
  btc_chaindb_set_cache(chain->db, cache_size);
}

void
btc_chain_on_block(btc_chain_t *chain, btc_chain_block_cb *handler) {
  chain->on_block = handler;
}

void
btc_chain_on_connect(btc_chain_t *chain, btc_chain_connect_cb *handler) {
  chain->on_connect = handler;
}

void
btc_chain_on_disconnect(btc_chain_t *chain,
                        btc_chain_connect_cb *handler) {
  chain->on_disconnect = handler;
}

void
btc_chain_on_reorganize(btc_chain_t *chain,
                        btc_chain_reorganize_cb *handler) {
  chain->on_reorganize = handler;
}

void
btc_chain_on_badorphan(btc_chain_t *chain,
                       btc_chain_badorphan_cb *handler) {
  chain->on_badorphan = handler;
}

void
btc_chain_set_context(btc_chain_t *chain, void *arg) {
  chain->arg = arg;
}

static void
btc_chain_get_deployment_state(btc_chain_t *chain,
                               btc_deployment_state_t *state) {
  const btc_entry_t *tip = chain->tip;

  btc_chain_get_deployments(chain, state, tip->header.time, tip->prev);
}

static void
btc_chain_maybe_sync(btc_chain_t *chain) {
  const btc_network_t *network = chain->network;
  int64_t now;

  if (chain->synced)
    return;

  if (chain->flags & BTC_CHAIN_CHECKPOINTS) {
    if (chain->height < network->last_checkpoint)
      return;
  }

  if (btc_hash_compare(chain->tip->chainwork, network->pow.chainwork) < 0)
    return;

  now = btc_timedata_now(chain->timedata);

  if (chain->tip->header.time < now - network->block.max_tip_age)
    return;

  btc_log_info(chain, "Chain is fully synced (height=%d).", chain->height);

  chain->synced = 1;
}

int
btc_chain_open(btc_chain_t *chain, const char *prefix, unsigned int flags) {
  btc_log_info(chain, "Chain is loading.");

  chain->flags = flags;

  if (!btc_chaindb_open(chain->db, prefix, flags))
    return 0;

#if defined(_WIN32) || defined(BTC_PTHREAD)
  if (chain->threads > 0)
    chain->workers = btc_workers_create(chain->threads, 128);
#endif

  chain->tip = (btc_entry_t *)btc_chaindb_tail(chain->db);
  chain->height = chain->tip->height;
  chain->synced = 0;

  btc_chain_get_deployment_state(chain, &chain->state);

  if (chain->flags & BTC_CHAIN_CHECKPOINTS)
    btc_log_info(chain, "Checkpoints are enabled.");

  btc_log_info(chain, "Chain Height: %d", chain->height);

  btc_chain_maybe_sync(chain);

  return 1;
}

void
btc_chain_close(btc_chain_t *chain) {
  btc_log_info(chain, "Closing chain.");

  if (chain->workers != NULL) {
    btc_workers_destroy(chain->workers);
    chain->workers = NULL;
  }

  btc_chaindb_close(chain->db);
}

static void
btc_chain_add_orphan(btc_chain_t *chain, btc_orphan_t *orphan) {
  btc_header_t *hdr = &orphan->block->header;

  CHECK(btc_hashmap_put(&chain->orphan_map, orphan->hash, orphan));
  CHECK(btc_hashmap_put(&chain->orphan_prev, hdr->prev_block, orphan));
}

static void
btc_chain_remove_orphan(btc_chain_t *chain, const btc_orphan_t *orphan) {
  const btc_header_t *hdr = &orphan->block->header;

  CHECK(btc_hashmap_del(&chain->orphan_map, orphan->hash));
  CHECK(btc_hashmap_del(&chain->orphan_prev, hdr->prev_block));
}

int
btc_chain_has_orphan(btc_chain_t *chain, const uint8_t *hash) {
  return btc_hashmap_has(&chain->orphan_map, hash);
}

static void
btc_chain_limit_orphans(btc_chain_t *chain) {
  int64_t now = btc_time_msec();
  btc_orphan_t *oldest = NULL;
  btc_mapiter_t it;

  btc_map_each(&chain->orphan_map, it) {
    btc_orphan_t *orphan = chain->orphan_map.vals[it];

    if (now >= orphan->time + 60 * 60 * 1000) {
      btc_chain_remove_orphan(chain, orphan);
      btc_orphan_destroy(orphan);
      continue;
    }

    if (oldest == NULL || orphan->time < oldest->time)
      oldest = orphan;
  }

  if (chain->orphan_map.size < 20)
    return;

  if (oldest != NULL) {
    btc_chain_remove_orphan(chain, oldest);
    btc_orphan_destroy(oldest);
  }
}

static btc_orphan_t *
btc_chain_resolve_orphan(btc_chain_t *chain, const uint8_t *hash) {
  btc_orphan_t *orphan = btc_hashmap_get(&chain->orphan_prev, hash);

  if (orphan == NULL)
    return NULL;

  btc_chain_remove_orphan(chain, orphan);

  return orphan;
}

static void
btc_chain_store_orphan(btc_chain_t *chain,
                       const btc_block_t *block,
                       unsigned int id) {
  const btc_header_t *hdr = &block->header;
  int32_t height = btc_block_coinbase_height(block);
  btc_orphan_t *orphan;

  orphan = btc_hashmap_get(&chain->orphan_prev, hdr->prev_block);

  /* The orphan chain forked. */
  if (orphan != NULL) {
    btc_log_warn(chain, "Removing forked orphan block: %H (%d).",
                        orphan->hash, height);

    btc_chain_remove_orphan(chain, orphan);
    btc_orphan_destroy(orphan);
  }

  btc_chain_limit_orphans(chain);

  orphan = btc_orphan_create();
  orphan->block = btc_block_refconst(block);
  orphan->id = id;
  orphan->time = btc_time_msec();

  btc_header_hash(orphan->hash, hdr);

  btc_chain_add_orphan(chain, orphan);

  btc_log_debug(chain, "Storing orphan block: %H (%d).",
                       orphan->hash, height);
}

static int
btc_chain_has_next_orphan(btc_chain_t *chain, const uint8_t *hash) {
  return btc_hashmap_has(&chain->orphan_prev, hash);
}

static void
btc_chain_set_invalid(btc_chain_t *chain, const uint8_t *hash) {
  uint8_t *key = btc_hash_clone(hash);

  if (!btc_hashset_put(&chain->invalid, key))
    btc_free(key); /* Should never happen. */
}

BTC_UNUSED static void
btc_chain_remove_invalid(btc_chain_t *chain, const uint8_t *hash) {
  uint8_t *key = btc_hashset_del(&chain->invalid, hash);

  if (key != NULL)
    btc_free(key);
}

int
btc_chain_has_invalid(btc_chain_t *chain, const uint8_t *hash) {
  return btc_hashset_has(&chain->invalid, hash);
}

static int
btc_chain_is_invalid(btc_chain_t *chain,
                     const uint8_t *hash,
                     const btc_header_t *hdr) {
  if (btc_hashset_has(&chain->invalid, hash))
    return 1;

  if (btc_hashset_has(&chain->invalid, hdr->prev_block)) {
    btc_chain_set_invalid(chain, hash);
    return 1;
  }

  return 0;
}

static int
btc_chain_verify_checkpoint(btc_chain_t *chain,
                            const btc_entry_t *prev,
                            const uint8_t *hash) {
  const btc_network_t *network = chain->network;
  int32_t height = prev->height + 1;
  const btc_checkpoint_t *chk;

  if (!(chain->flags & BTC_CHAIN_CHECKPOINTS))
    return 1;

  chk = btc_network_checkpoint(network, height);

  if (chk == NULL)
    return 1;

  if (btc_hash_equal(hash, chk->hash)) {
    btc_log_debug(chain, "Hit checkpoint block %H (%d).", hash, height);
    return 1;
  }

  /* Someone is either mining on top of
     an old block for no reason, or the
     consensus protocol is broken and
     there was a 20k+ block reorg. */
  btc_log_warn(chain, "Checkpoint mismatch: height=%d expected=%H received=%H",
                      height, chk->hash, hash);

  return 0;
}

static const btc_entry_t *
btc_chain_last_checkpoint(btc_chain_t *chain) {
  const btc_network_t *network = chain->network;
  int length = network->checkpoints.length;
  const btc_checkpoint_t *chk;
  const btc_entry_t *entry;
  int i;

  for (i = length - 1; i >= 0; i--) {
    chk = &network->checkpoints.items[i];
    entry = btc_chaindb_by_hash(chain->db, chk->hash);

    if (entry != NULL)
      return entry;
  }

  return NULL;
}

static int
btc_chain_is_historical(btc_chain_t *chain, const btc_entry_t *prev) {
  if (chain->flags & BTC_CHAIN_CHECKPOINTS) {
    if (prev->height + 1 <= chain->network->last_checkpoint)
      return 1;
  }

  return 0;
}

static const btc_entry_t *
btc_chain_get_ancestor(btc_chain_t *chain,
                       const btc_entry_t *entry,
                       int32_t height) {
  if (height < 0)
    return NULL;

  CHECK(height <= entry->height);

  if (btc_chaindb_is_main(chain->db, entry))
    return btc_chaindb_by_height(chain->db, height);

  while (entry->height != height)
    entry = entry->prev;

  return entry;
}

static uint32_t
btc_chain_max_target(btc_chain_t *chain, uint32_t base, int64_t delta) {
  const btc_network_pow_t *pow = &chain->network->pow;
  uint32_t bits = pow->bits;
  mpz_t target;

  if (pow->no_retargeting)
    return pow->bits;

  if (pow->target_reset && delta > pow->target_spacing * 2)
    return pow->bits;

  mpz_init_set_compact(target, base);

  while (delta > 0 && mpz_cmp(target, chain->limit) < 0) {
    mpz_mul_2exp(target, target, 2);

    delta -= pow->target_timespan * 4;
  }

  if (mpz_cmp(target, chain->limit) < 0)
    bits = mpz_get_compact(target);

  mpz_clear(target);

  return bits;
}

static uint32_t
btc_chain_retarget(btc_chain_t *chain,
                   const btc_entry_t *last,
                   const btc_entry_t *first) {
  const btc_network_pow_t *pow = &chain->network->pow;
  int64_t target_timespan = pow->target_timespan;
  int64_t actual_timespan;
  uint32_t bits = pow->bits;
  mpz_t target;

  if (pow->no_retargeting)
    return last->header.bits;

  mpz_init_set_compact(target, last->header.bits);

  actual_timespan = last->header.time - first->header.time;

  if (actual_timespan < target_timespan / 4)
    actual_timespan = target_timespan / 4;

  if (actual_timespan > target_timespan * 4)
    actual_timespan = target_timespan * 4;

  mpz_mul_ui(target, target, actual_timespan);
  mpz_quo_ui(target, target, target_timespan);

  if (mpz_cmp(target, chain->limit) < 0)
    bits = mpz_get_compact(target);

  if (bits != last->header.bits)
    btc_log_debug(chain, "Retargeting to: %#.8x.", bits);

  mpz_clear(target);

  return bits;
}

uint32_t
btc_chain_get_target(btc_chain_t *chain,
                     int64_t time,
                     const btc_entry_t *prev) {
  const btc_network_t *network = chain->network;
  const btc_network_pow_t *pow = &network->pow;
  const btc_entry_t *last = prev;
  const btc_entry_t *first;
  int32_t height;

  if (last == NULL) {
    CHECK(time == network->genesis.header.time);
    return pow->bits;
  }

  /* Do not retarget. */
  if ((last->height + 1) % pow->retarget_interval != 0) {
    if (pow->target_reset) {
      /* Special behavior for testnet. */
      if (time > last->header.time + pow->target_spacing * 2)
        return pow->bits;

      while (last->prev != NULL) {
        if (last->height % pow->retarget_interval == 0)
          break;

        if (last->header.bits != pow->bits)
          break;

        last = last->prev;
      }
    }

    return last->header.bits;
  }

  /* Back 2 weeks. */
  height = last->height - (pow->retarget_interval - 1);

  CHECK(height >= 0);

  first = btc_chain_get_ancestor(chain, last, height);

  CHECK(first != NULL);

  return btc_chain_retarget(chain, last, first);
}

uint32_t
btc_chain_get_current_target(btc_chain_t *chain) {
  int64_t time = btc_timedata_now(chain->timedata);
  return btc_chain_get_target(chain, time, chain->tip);
}

static int
btc_chain_get_state(btc_chain_t *chain,
                    const btc_entry_t *prev,
                    const btc_deployment_t *deployment) {
  int32_t threshold = chain->network->activation_threshold;
  int32_t window = chain->network->miner_window;
  const btc_entry_t *entry, *block;
  int bit = deployment->bit;
  btc_vector_t compute;
  int32_t height, count;
  int i, state, cached;
  int64_t time;

  if (deployment->threshold != -1)
    threshold = deployment->threshold;

  if (deployment->window != -1)
    window = deployment->window;

  if (prev == NULL)
    return BTC_STATE_DEFINED;

  if (((prev->height + 1) % window) != 0) {
    height = prev->height - ((prev->height + 1) % window);
    prev = btc_chain_get_ancestor(chain, prev, height);

    if (prev == NULL)
      return BTC_STATE_DEFINED;

    CHECK(prev->height == height);
    CHECK(((prev->height + 1) % window) == 0);
  }

  entry = prev;
  state = BTC_STATE_DEFINED;

  btc_vector_init(&compute);

  while (entry != NULL) {
    cached = btc_statecache_get(&chain->cache, bit, entry);

    if (cached != -1) {
      state = cached;
      break;
    }

    time = btc_entry_median_time(entry);

    if (time < deployment->start_time) {
      state = BTC_STATE_DEFINED;
      btc_statecache_set(&chain->cache, bit, entry, state);
      break;
    }

    btc_vector_push(&compute, entry);

    height = entry->height - window;

    entry = btc_chain_get_ancestor(chain, entry, height);
  }

  while (compute.length > 0) {
    entry = btc_vector_pop(&compute);

    switch (state) {
      case BTC_STATE_DEFINED: {
        time = btc_entry_median_time(entry);

        if (time >= deployment->timeout) {
          state = BTC_STATE_FAILED;
          break;
        }

        if (time >= deployment->start_time) {
          state = BTC_STATE_STARTED;
          break;
        }

        break;
      }

      case BTC_STATE_STARTED: {
        time = btc_entry_median_time(entry);

        if (time >= deployment->timeout) {
          state = BTC_STATE_FAILED;
          break;
        }

        block = entry;
        count = 0;

        for (i = 0; i < window; i++) {
          if (btc_has_versionbit(block->header.version, bit))
            count++;

          if (count >= threshold) {
            state = BTC_STATE_LOCKED_IN;
            break;
          }

          block = block->prev;

          CHECK(block != NULL);
        }

        break;
      }

      case BTC_STATE_LOCKED_IN: {
        state = BTC_STATE_ACTIVE;
        break;
      }

      case BTC_STATE_FAILED:
      case BTC_STATE_ACTIVE: {
        break;
      }

      default: {
        btc_abort(); /* LCOV_EXCL_LINE */
        break;
      }
    }

    btc_statecache_set(&chain->cache, bit, entry, state);
  }

  btc_vector_clear(&compute);

  return state;
}

static int
btc_chain_is_active(btc_chain_t *chain,
                    const btc_entry_t *prev,
                    const btc_deployment_t *deployment) {
  return btc_chain_get_state(chain, prev, deployment) == BTC_STATE_ACTIVE;
}

void
btc_chain_get_deployments(btc_chain_t *chain,
                          btc_deployment_state_t *state,
                          int64_t time,
                          const btc_entry_t *prev) {
  int32_t height = prev != NULL ? prev->height + 1 : 0;
  const btc_network_t *network = chain->network;
  const btc_deployment_t *deploy;
  int active;

  btc_deployment_state_init(state);

  /* For some reason bitcoind has p2sh in the
   * mandatory flags by default, when in reality
   * it wasn't activated until march 30th 2012.
   * The first p2sh output and redeem script
   * appeared on march 7th 2012, only it did
   * not have a signature.
   *
   * See: 6a26d2ecb67f27d1fa5524763b49029d7106e91e3cc05743073461a719776192
   *      9c08a4d78931342b37fd5f72900fb9983087e6f46c4a097d8a1f52c74e28eaf6
   */
  if (time >= BTC_BIP16_TIME)
    state->flags |= BTC_SCRIPT_VERIFY_P2SH;

  /* Coinbase heights are now enforced (bip34). */
  if (height >= network->softforks.bip34.height)
    state->bip34 = 1;

  /* Signature validation is now enforced (bip66). */
  if (height >= network->softforks.bip66.height)
    state->flags |= BTC_SCRIPT_VERIFY_DERSIG;

  /* CHECKLOCKTIMEVERIFY is now usable (bip65). */
  if (height >= network->softforks.bip65.height)
    state->flags |= BTC_SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;

  /* CHECKSEQUENCEVERIFY and median time
     past locktimes are now usable (bip9 & bip113). */
  deploy = btc_network_deployment(network, "csv");

  if (deploy != NULL)
    active = btc_chain_is_active(chain, prev, deploy);
  else
    active = (height >= network->softforks.csv.height);

  if (active) {
    state->flags |= BTC_SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;
    state->lock_flags |= BTC_LOCKTIME_VERIFY_SEQUENCE;
    state->lock_flags |= BTC_LOCKTIME_MEDIAN_TIME_PAST;
  }

  /* Segregrated witness (bip141) is now usable.
     along with SCRIPT_VERIFY_NULLDUMMY (bip147). */
  deploy = btc_network_deployment(network, "segwit");

  if (deploy != NULL)
    active = btc_chain_is_active(chain, prev, deploy);
  else
    active = (height >= network->softforks.segwit.height);

  if (active) {
    state->flags |= BTC_SCRIPT_VERIFY_WITNESS;
    state->flags |= BTC_SCRIPT_VERIFY_NULLDUMMY;
  }
}

static int
btc_chain_throw(btc_chain_t *chain,
                const btc_header_t *header,
                unsigned int code,
                const char *reason,
                int score,
                int malleated) {
  const char *str = btc_reject_code(code);
  uint8_t *hash = chain->error.hash;

  btc_header_hash(hash, header);

  chain->error.code = code;
  chain->error.reason = reason;
  chain->error.score = score;
  chain->error.malleated = malleated;

  btc_log_warn(chain, "Verification error: %s (code=%s score=%d hash=%H)",
                      reason, str, score, hash);

  return 0;
}

static int
btc_chain_check_target(btc_chain_t *chain, const btc_header_t *hdr) {
  const btc_entry_t *chk;
  int64_t delta;
  uint32_t max;

  if (!(chain->flags & BTC_CHAIN_CHECKPOINTS))
    return 1;

  if (btc_hash_equal(hdr->prev_block, chain->tip->hash))
    return 1;

  chk = btc_chain_last_checkpoint(chain);

  if (chk == NULL)
    return 1;

  delta = hdr->time - chk->header.time;

  if (delta < 0) {
    /* Block with timestamp before last checkpoint. */
    return btc_chain_throw(chain, hdr,
                           BTC_REJECT_CHECKPOINT,
                           "time-too-old",
                           100,
                           1);
  }

  max = btc_chain_max_target(chain, chk->header.bits, delta);

  if (btc_compact_compare(hdr->bits, max) > 0) {
    /* Block with too little proof-of-work. */
    return btc_chain_throw(chain, hdr,
                           BTC_REJECT_INVALID,
                           "bad-diffbits",
                           100,
                           1);
  }

  return 1;
}

static int
btc_chain_verify(btc_chain_t *chain,
                 btc_deployment_state_t *state,
                 const btc_block_t *block,
                 const btc_entry_t *prev) {
  const btc_header_t *hdr = &block->header;
  const btc_network_t *network = chain->network;
  const uint8_t *commit_hash = NULL;
  uint8_t hash[32];
  uint8_t root[32];
  int64_t time, mtp;
  int32_t height;
  uint32_t bits;
  size_t i;

  btc_deployment_state_init(state);

  /* Extra sanity check. */
  if (!btc_hash_equal(hdr->prev_block, prev->hash)) {
    return btc_chain_throw(chain, hdr,
                           BTC_REJECT_INVALID,
                           "bad-prevblk",
                           10,
                           0);
  }

  /* Verify a checkpoint if there is one. */
  btc_header_hash(hash, hdr);

  if (!btc_chain_verify_checkpoint(chain, prev, hash)) {
    return btc_chain_throw(chain, hdr,
                           BTC_REJECT_CHECKPOINT,
                           "checkpoint mismatch",
                           100,
                           0);
  }

  /* Ensure the POW is what we expect. */
  bits = btc_chain_get_target(chain, hdr->time, prev);

  if (hdr->bits != bits) {
    return btc_chain_throw(chain, hdr,
                           BTC_REJECT_INVALID,
                           "bad-diffbits",
                           100,
                           0);
  }

  /* Ensure the timestamp is correct. */
  mtp = btc_entry_median_time(prev);

  if (hdr->time <= mtp) {
    return btc_chain_throw(chain, hdr,
                           BTC_REJECT_INVALID,
                           "time-too-old",
                           0,
                           0);
  }

  /* Calculate height of current block. */
  height = prev->height + 1;

  /* Only allow version 2 blocks (coinbase height)
     once the majority of blocks are using it. */
  if (hdr->version < 2 && height >= network->softforks.bip34.height) {
    return btc_chain_throw(chain, hdr,
                           BTC_REJECT_OBSOLETE,
                           "bad-version",
                           0,
                           0);
  }

  /* Only allow version 3 blocks (sig validation)
     once the majority of blocks are using it. */
  if (hdr->version < 3 && height >= network->softforks.bip66.height) {
    return btc_chain_throw(chain, hdr,
                           BTC_REJECT_OBSOLETE,
                           "bad-version",
                           0,
                           0);
  }

  /* Only allow version 4 blocks (checklocktimeverify)
     once the majority of blocks are using it. */
  if (hdr->version < 4 && height >= network->softforks.bip65.height) {
    return btc_chain_throw(chain, hdr,
                           BTC_REJECT_OBSOLETE,
                           "bad-version",
                           0,
                           0);
  }

  /* Get the new deployment state. */
  btc_chain_get_deployments(chain, state, hdr->time, prev);

  /* Get timestamp for tx_is_final(). */
  time = hdr->time;

  if (state->lock_flags & BTC_LOCKTIME_MEDIAN_TIME_PAST)
    time = mtp;

  /* Transactions must be finalized with
     regards to nSequence and nLockTime. */
  for (i = 0; i < block->txs.length; i++) {
    const btc_tx_t *tx = block->txs.items[i];

    if (!btc_tx_is_final(tx, height, time)) {
      return btc_chain_throw(chain, hdr,
                             BTC_REJECT_INVALID,
                             "bad-txns-nonfinal",
                             10,
                             0);
    }
  }

  /* Make sure the height contained
     in the coinbase is correct. */
  if (state->bip34) {
    if (btc_block_coinbase_height(block) != height) {
      return btc_chain_throw(chain, hdr,
                             BTC_REJECT_INVALID,
                             "bad-cb-height",
                             100,
                             0);
    }
  }

  /* Check the commitment hash for segwit. */
  if (state->flags & BTC_SCRIPT_VERIFY_WITNESS) {
    commit_hash = btc_block_get_commitment_hash(block);

    if (commit_hash) {
      /* These are totally malleable. Someone
         may have even accidentally sent us
         the non-witness version of the block.
         We don't want to consider this block
         "invalid" if either of these checks
         fail. */
      if (!btc_block_witness_nonce(block)) {
        return btc_chain_throw(chain, hdr,
                               BTC_REJECT_INVALID,
                               "bad-witness-nonce-size",
                               100,
                               1);
      }

      CHECK(btc_block_create_commitment_hash(root, block));

      if (!btc_hash_equal(commit_hash, root)) {
        return btc_chain_throw(chain, hdr,
                               BTC_REJECT_INVALID,
                               "bad-witness-merkle-match",
                               100,
                               1);
      }
    }
  }

  /* Blocks that do not commit to
     witness data cannot contain it. */
  if (!commit_hash) {
    if (btc_block_has_witness(block)) {
      return btc_chain_throw(chain, hdr,
                             BTC_REJECT_INVALID,
                             "unexpected-witness",
                             100,
                             1);
    }
  }

  /* Check block weight (different from block size
     check in non-contextual verification). */
  if (btc_block_weight(block) > BTC_MAX_BLOCK_WEIGHT) {
    return btc_chain_throw(chain, hdr,
                           BTC_REJECT_INVALID,
                           "bad-blk-weight",
                           100,
                           0);
  }

  return 1;
}

static int
btc_chain_verify_duplicates(btc_chain_t *chain,
                            const btc_block_t *block,
                            const btc_entry_t *prev) {
  /**
   * Determine whether to check block for duplicate txids in blockchain
   * history (BIP30). If we're on a chain that has bip34 activated, we
   * can skip this.
   *
   * See: https://github.com/bitcoin/bips/blob/master/bip-0030.mediawiki
   */
  const btc_network_t *network = chain->network;
  const btc_header_t *hdr = &block->header;
  uint8_t hash[32];
  size_t i;

  btc_header_hash(hash, hdr);

  for (i = 0; i < block->txs.length; i++) {
    const btc_tx_t *tx = block->txs.items[i];
    const btc_checkpoint_t *chk;

    if (!btc_chaindb_has_coins(chain->db, tx))
      continue;

    chk = btc_network_bip30(network, prev->height + 1);

    /* Blocks 91842 and 91880 created duplicate
       txids by using the same exact output script
       and extraNonce. */
    if (chk == NULL || !btc_hash_equal(hash, chk->hash)) {
      return btc_chain_throw(chain, hdr,
                             BTC_REJECT_INVALID,
                             "bad-txns-BIP30",
                             100,
                             0);
    }
  }

  return 1;
}

static btc_view_t *
btc_chain_update_inputs(btc_chain_t *chain,
                        const btc_block_t *block,
                        const btc_entry_t *prev) {
  const btc_tx_t *cb = block->txs.items[0];
  btc_view_t *view = btc_view_create();
  int32_t height = prev->height + 1;
  size_t i;

  btc_view_add(view, cb, height, 0);

  for (i = 1; i < block->txs.length; i++) {
    const btc_tx_t *tx = block->txs.items[i];

    CHECK(btc_chaindb_spend(chain->db, view, tx));

    btc_view_add(view, tx, height, 0);
  }

  return view;
}

int
btc_chain_verify_final(btc_chain_t *chain,
                       const btc_entry_t *prev,
                       const btc_tx_t *tx,
                       unsigned int flags) {
  int32_t height = prev->height + 1;

  /* We can skip MTP if the locktime is height. */
  if (tx->locktime < BTC_LOCKTIME_THRESHOLD)
    return btc_tx_is_final(tx, height, -1);

  if (flags & BTC_LOCKTIME_MEDIAN_TIME_PAST) {
    int64_t ts = btc_entry_median_time(prev);
    return btc_tx_is_final(tx, height, ts);
  }

  return btc_tx_is_final(tx, height, btc_timedata_now(chain->timedata));
}

int
btc_chain_verify_locks(btc_chain_t *chain,
                       const btc_entry_t *prev,
                       const btc_tx_t *tx,
                       const btc_view_t *view,
                       unsigned int flags) {
  int32_t min_height = -1;
  int64_t min_time = -1;
  size_t i;

  if (!(flags & BTC_LOCKTIME_VERIFY_SEQUENCE))
    return 1;

  if (btc_tx_is_coinbase(tx) || tx->version < 2)
    return 1;

  for (i = 0; i < tx->inputs.length; i++) {
    const btc_input_t *input = tx->inputs.items[i];
    uint32_t sequence = input->sequence;
    const btc_entry_t *entry;
    const btc_coin_t *coin;
    uint32_t masked;
    int32_t height;
    int64_t time;

    if (sequence & BTC_SEQUENCE_DISABLE_FLAG)
      continue;

    coin = btc_view_get(view, &input->prevout);

    if (coin == NULL || coin->height == -1)
      height = chain->height + 1;
    else
      height = coin->height;

    masked = sequence & BTC_SEQUENCE_MASK;

    if (!(sequence & BTC_SEQUENCE_TYPE_FLAG)) {
      height += (int32_t)masked - 1;

      if (height > min_height)
        min_height = height;

      continue;
    }

    if (height > 0)
      height -= 1;

    entry = btc_chain_get_ancestor(chain, prev, height);

    CHECK(entry != NULL);

    masked <<= BTC_SEQUENCE_GRANULARITY;

    time = btc_entry_median_time(entry) + ((int64_t)masked - 1);

    if (time > min_time)
      min_time = time;
  }

  if (min_height >= prev->height + 1)
    return 0;

  if (min_time >= btc_entry_median_time(prev))
    return 0;

  return 1;
}

static btc_view_t *
btc_chain_verify_inputs(btc_chain_t *chain,
                        const btc_block_t *block,
                        const btc_entry_t *prev,
                        const btc_deployment_state_t *state) {
  const btc_header_t *hdr = &block->header;
  int32_t interval = chain->network->halving_interval;
  btc_view_t *view = btc_view_create();
  int32_t height = prev->height + 1;
  btc_verify_error_t err;
  int64_t reward = 0;
  int sigops = 0;
  size_t i;

  /* Check all transactions. */
  for (i = 0; i < block->txs.length; i++) {
    const btc_tx_t *tx = block->txs.items[i];

    /* Ensure tx is not double spending an output. */
    if (i > 0) {
      if (!btc_chaindb_spend(chain->db, view, tx)) {
        btc_chain_throw(chain, hdr,
                        BTC_REJECT_INVALID,
                        "bad-txns-inputs-missingorspent",
                        100,
                        0);
        goto fail;
      }
    }

    /* Verify sequence locks. */
    if (i > 0 && tx->version >= 2) {
      if (!btc_chain_verify_locks(chain, prev, tx, view, state->lock_flags)) {
        btc_chain_throw(chain, hdr,
                        BTC_REJECT_INVALID,
                        "bad-txns-nonfinal",
                        100,
                        0);
        goto fail;
      }
    }

    /* Count sigops (legacy + scripthash? + witness?). */
    sigops += btc_tx_sigops_cost(tx, view, state->flags);

    if (sigops > BTC_MAX_BLOCK_SIGOPS_COST) {
      btc_chain_throw(chain, hdr,
                      BTC_REJECT_INVALID,
                      "bad-blk-sigops",
                      100,
                      0);
      goto fail;
    }

    /* Contextual sanity checks. */
    if (i > 0) {
      int64_t fee = btc_tx_check_inputs(&err, tx, view, height);

      if (fee == -1) {
        btc_chain_throw(chain, hdr,
                        BTC_REJECT_INVALID,
                        err.reason,
                        err.score,
                        0);
        goto fail;
      }

      reward += fee;

      if (reward < 0 || reward > BTC_MAX_MONEY) {
        btc_chain_throw(chain, hdr,
                        BTC_REJECT_INVALID,
                        "bad-cb-amount",
                        100,
                        0);
        goto fail;
      }
    }

    btc_view_add(view, tx, height, 0);
  }

  /* Make sure the miner isn't trying to conjure more coins. */
  reward += btc_get_reward(height, interval);

  if (btc_block_claimed(block) > reward) {
    btc_chain_throw(chain, hdr,
                    BTC_REJECT_INVALID,
                    "bad-cb-amount",
                    100,
                    0);
    goto fail;
  }

  if (chain->workers != NULL) {
    btc_checker_t checker;

    /* Verify all transactions in parallel. */
    btc_checker_init(&checker, chain->workers);

    for (i = 1; i < block->txs.length; i++) {
      const btc_tx_t *tx = block->txs.items[i];

      btc_checker_push(&checker, tx, view, state->flags);
    }

    if (!btc_checker_verify(&checker)) {
      btc_chain_throw(chain, hdr,
                      BTC_REJECT_INVALID,
                      "mandatory-script-verify-flag-failed",
                      100,
                      0);
      goto fail;
    }
  } else {
    /* Verify all transactions. */
    for (i = 1; i < block->txs.length; i++) {
      const btc_tx_t *tx = block->txs.items[i];

      if (!btc_tx_verify(tx, view, state->flags)) {
        btc_chain_throw(chain, hdr,
                        BTC_REJECT_INVALID,
                        "mandatory-script-verify-flag-failed",
                        100,
                        0);
        goto fail;
      }
    }
  }

  return view;
fail:
  btc_view_destroy(view);
  return NULL;
}

static btc_view_t *
btc_chain_verify_context(btc_chain_t *chain,
                         btc_deployment_state_t *state,
                         const btc_block_t *block,
                         const btc_entry_t *prev) {
  /* Initial semi-contextual verification. */
  if (!btc_chain_verify(chain, state, block, prev))
    return NULL;

  /* Skip everything if we're using checkpoints. */
  if (btc_chain_is_historical(chain, prev))
    return btc_chain_update_inputs(chain, block, prev);

  /* BIP30 - Verify there are no duplicate txids.
     Note that BIP34 made it impossible to create
     duplicate txids. */
  if (!state->bip34) {
    if (!btc_chain_verify_duplicates(chain, block, prev))
      return NULL;
  }

  /* Verify scripts, spend and add coins. */
  return btc_chain_verify_inputs(chain, block, prev, state);
}

static int
btc_chain_reconnect(btc_chain_t *chain, btc_entry_t *entry) {
  const btc_header_t *hdr = &entry->header;
  btc_deployment_state_t state;
  btc_block_t *block;
  btc_view_t *view;
  int ret = 0;

  block = btc_chaindb_get_block(chain->db, entry);

  if (block == NULL) {
    btc_log_error(chain, "Block data not found: %H (%d).",
                         entry->hash, entry->height);

    return btc_chain_throw(chain, hdr,
                           BTC_REJECT_INTERNAL,
                           "blk-notfound",
                           0,
                           1);
  }

  view = btc_chain_verify_context(chain, &state, block, entry->prev);

  if (view == NULL) {
    if (!chain->error.malleated)
      btc_chain_set_invalid(chain, entry->hash);

    btc_log_warn(chain, "Tried to reconnect invalid block: %H (%d).",
                        entry->hash, entry->height);

    goto fail;
  }

  CHECK(btc_chaindb_reconnect(chain->db, entry, block, view));

  chain->tip = entry;
  chain->height = entry->height;
  chain->state = state;

  if (chain->on_connect != NULL)
    chain->on_connect(entry, block, view, chain->arg);

  btc_view_destroy(view);

  ret = 1;
fail:
  btc_block_destroy(block);
  return ret;
}

static int
btc_chain_disconnect(btc_chain_t *chain, btc_entry_t *entry) {
  const btc_header_t *hdr = &entry->header;
  btc_entry_t *tip = entry->prev;
  btc_deployment_state_t state;
  btc_block_t *block;
  btc_view_t *view;

  block = btc_chaindb_get_block(chain->db, entry);

  if (block == NULL) {
    btc_log_error(chain, "Block data not found: %H (%d).",
                         entry->hash, entry->height);

    return btc_chain_throw(chain, hdr,
                           BTC_REJECT_INTERNAL,
                           "blk-notfound",
                           0,
                           1);
  }

  view = btc_chaindb_disconnect(chain->db, entry, block);

  CHECK(view != NULL);

  btc_chain_get_deployments(chain, &state, tip->header.time, tip->prev);

  chain->tip = tip;
  chain->height = tip->height;
  chain->state = state;

  if (chain->on_disconnect != NULL)
    chain->on_disconnect(entry, block, view, chain->arg);

  btc_view_destroy(view);
  btc_block_destroy(block);

  return 1;
}

static const btc_entry_t *
btc_chain_find_fork(btc_chain_t *chain, const btc_entry_t *entry) {
  if (entry->height > chain->height)
    entry = btc_chain_get_ancestor(chain, entry, chain->height);

  while (!btc_chaindb_is_main(chain->db, entry))
    entry = entry->prev;

  return entry;
}

static int
btc_chain_reorganize(btc_chain_t *chain,
                     const btc_entry_t *fork,
                     btc_entry_t *new_tip) {
  btc_entry_t *old_tip = chain->tip;
  btc_vector_t disconnect, connect;
  btc_entry_t *entry;
  int ret = 1;
  size_t i;

  btc_vector_init(&disconnect);
  btc_vector_init(&connect);

  /* Blocks to disconnect. */
  for (entry = old_tip; entry != fork; entry = entry->prev)
    btc_vector_push(&disconnect, entry);

  /* Blocks to connect. */
  for (entry = new_tip; entry != fork; entry = entry->prev)
    btc_vector_push(&connect, entry);

  /* Disconnect blocks and transactions. */
  for (i = 0; i < disconnect.length; i++)
    CHECK(btc_chain_disconnect(chain, disconnect.items[i]));

  /* Connect blocks and transactions. */
  for (i = connect.length - 1; i != (size_t)-1; i--) {
    if (!btc_chain_reconnect(chain, connect.items[i])) {
      if (!chain->error.malleated) {
        while (i--) {
          entry = connect.items[i];
          btc_chain_set_invalid(chain, entry->hash);
        }
      }
      ret = 0;
      break;
    }
  }

  btc_vector_clear(&disconnect);
  btc_vector_clear(&connect);

  return ret;
}

static int
btc_chain_save_alternate(btc_chain_t *chain,
                         btc_entry_t *entry,
                         const btc_block_t *block) {
  const btc_header_t *hdr = &block->header;
  btc_deployment_state_t state;

  /* Do not accept forked chain older than the last checkpoint. */
  if (chain->flags & BTC_CHAIN_CHECKPOINTS) {
    const btc_entry_t *chk = btc_chain_last_checkpoint(chain);

    if (chk != NULL && entry->height < chk->height) {
      return btc_chain_throw(chain, hdr,
                             BTC_REJECT_CHECKPOINT,
                             "bad-fork-prior-to-checkpoint",
                             100,
                             0);
    }
  }

  /* Do as much verification as we can before saving. */
  if (!btc_chain_verify(chain, &state, block, entry->prev)) {
    if (!chain->error.malleated)
      btc_chain_set_invalid(chain, entry->hash);

    btc_log_warn(chain, "Invalid block on alternate chain: %H (%d).",
                        entry->hash, entry->height);

    return 0;
  }

  CHECK(btc_chaindb_save(chain->db, entry, block, NULL));

  btc_log_warn(chain, "Heads up: Competing chain at height %d:"
                      " tip-height=%d competitor-height=%d"
                      " tip-hash=%H competitor-hash=%H"
                      " tip-chainwork=%H competitor-chainwork=%H",
                      entry->height,
                      chain->tip->height,
                      entry->height,
                      chain->tip->hash,
                      entry->hash,
                      chain->tip->chainwork,
                      entry->chainwork);

  return 1;
}

static int
btc_chain_set_best_chain(btc_chain_t *chain,
                         btc_entry_t *entry,
                         const btc_block_t *block) {
  const btc_entry_t *fork = NULL;
  btc_entry_t *tip = chain->tip;
  btc_deployment_state_t state;
  btc_view_t *view;

  /* A higher fork has arrived. Time to reorganize the chain. */
  if (!btc_hash_equal(entry->header.prev_block, tip->hash)) {
    btc_log_warn(chain, "WARNING: Reorganizing chain.");

    fork = btc_chain_find_fork(chain, entry);

    if (!btc_chain_reorganize(chain, fork, entry->prev)) {
      if (btc_hash_compare(chain->tip->chainwork, tip->chainwork) < 0)
        CHECK(btc_chain_reorganize(chain, fork, tip));

      return 0;
    }
  }

  /* Otherwise, everything is in order. Do "contextual" verification
     on our block now that we're certain its previous block is in
     the chain. */
  view = btc_chain_verify_context(chain, &state, block, entry->prev);

  if (view == NULL) {
    if (!chain->error.malleated)
      btc_chain_set_invalid(chain, entry->hash);

    btc_log_warn(chain, "Tried to connect invalid block: %H (%d).",
                        entry->hash, entry->height);

    if (fork != NULL) {
      if (btc_hash_compare(chain->tip->chainwork, tip->chainwork) < 0)
        CHECK(btc_chain_reorganize(chain, fork, tip));
    }

    return 0;
  }

  /* Save block and connect inputs. */
  CHECK(btc_chaindb_save(chain->db, entry, block, view));

  chain->tip = entry;
  chain->height = entry->height;
  chain->state = state;

  if (chain->on_connect != NULL)
    chain->on_connect(entry, block, view, chain->arg);

  if (fork != NULL) {
    btc_log_warn(chain, "Chain reorganization: old=%H(%d) new=%H(%d)",
                        tip->hash, tip->height, entry->hash, entry->height);

    if (chain->on_reorganize != NULL)
      chain->on_reorganize(tip, entry, chain->arg);
  }

  if (chain->on_block != NULL)
    chain->on_block(block, entry, chain->arg);

  btc_view_destroy(view);

  return 1;
}

static const btc_entry_t *
btc_chain_connect(btc_chain_t *chain,
                  const btc_entry_t *prev,
                  const btc_block_t *block) {
  const btc_network_t *network = chain->network;
  const btc_header_t *hdr = &block->header;
  btc_entry_t *entry = btc_entry_create();
  int64_t now = btc_time_usec();
  size_t rss;

  /* Sanity check. */
  CHECK(btc_hash_equal(hdr->prev_block, prev->hash));

  /* Create a new chain entry. */
  btc_entry_set_block(entry, block, prev);

  /* The block is on a alternate chain if the chainwork
     is less than or equal to our tip's. Add the block
     but do _not_ connect the inputs. */
  if (btc_hash_compare(entry->chainwork, chain->tip->chainwork) <= 0) {
    /* Save block to an alternate chain. */
    if (!btc_chain_save_alternate(chain, entry, block)) {
      btc_entry_destroy(entry);
      return NULL;
    }
  } else {
    /* Attempt to add block to the chain index. */
    if (!btc_chain_set_best_chain(chain, entry, block)) {
      btc_entry_destroy(entry);
      return NULL;
    }
  }

  if (entry->height % 20 == 0 || entry->height >= network->block.slow_height) {
    btc_log_info(chain, "Block %H (%d) added to chain (txs=%zu time=%.2f).",
                        entry->hash, entry->height, block->txs.length,
                        (double)(btc_time_usec() - now) / 1000.0);

    if ((rss = btc_ps_rss()))
      btc_log_debug(chain, "Memory: rss=%zumb", rss / (1 << 20));
  }

  btc_chain_maybe_sync(chain);

  return entry;
}

static void
btc_chain_handle_orphans(btc_chain_t *chain, const btc_entry_t *entry) {
  btc_orphan_t *orphan = btc_chain_resolve_orphan(chain, entry->hash);

  while (orphan != NULL) {
    entry = btc_chain_connect(chain, entry, orphan->block);

    if (entry == NULL) {
      btc_log_warn(chain, "Could not resolve orphan block %H: %s.",
                          orphan->hash, chain->error.reason);

      if (chain->on_badorphan != NULL)
        chain->on_badorphan(&chain->error, orphan->id, chain->arg);

      btc_orphan_destroy(orphan);

      break;
    }

    btc_orphan_destroy(orphan);

    btc_log_debug(chain, "Orphan block was resolved: %H (%d).",
                         entry->hash, entry->height);

    orphan = btc_chain_resolve_orphan(chain, entry->hash);
  }
}

int
btc_chain_add(btc_chain_t *chain,
              const btc_block_t *block,
              unsigned int flags,
              unsigned int id) {
  const btc_network_t *network = chain->network;
  const btc_header_t *hdr = &block->header;
  const btc_entry_t *prev, *entry;
  uint8_t hash[32];

  btc_header_hash(hash, hdr);

  /* Special case for genesis block. */
  if (btc_hash_equal(hash, network->genesis.hash)) {
    btc_log_debug(chain, "Saw genesis block: %H.", hash);
    return btc_chain_throw(chain, hdr,
                           BTC_REJECT_DUPLICATE,
                           "duplicate",
                           0,
                           0);
  }

  /* If the block is already known to be
     an orphan, ignore it. */
  if (btc_chain_has_orphan(chain, hash)) {
    btc_log_debug(chain, "Already have orphan block: %H.", hash);
    return btc_chain_throw(chain, hdr,
                           BTC_REJECT_DUPLICATE,
                           "duplicate",
                           0,
                           0);
  }

  /* Do not revalidate known invalid blocks. */
  if (btc_chain_is_invalid(chain, hash, hdr)) {
    btc_log_debug(chain, "Invalid ancestors for block: %H.", hash);
    return btc_chain_throw(chain, hdr,
                           BTC_REJECT_DUPLICATE,
                           "duplicate",
                           100,
                           0);
  }

  /* Do we already have this block? */
  if (btc_chaindb_by_hash(chain->db, hash) != NULL) {
    btc_log_debug(chain, "Already have block: %H.", hash);
    return btc_chain_throw(chain, hdr,
                           BTC_REJECT_DUPLICATE,
                           "duplicate",
                           0,
                           0);
  }

  /* Check the PoW before doing anything. */
  if (flags & BTC_BLOCK_VERIFY_POW) {
    if (!btc_header_verify(hdr)) {
      btc_chain_set_invalid(chain, hash);
      return btc_chain_throw(chain, hdr,
                             BTC_REJECT_INVALID,
                             "high-hash",
                             50,
                             0);
    }
  }

  /* Non-contextual checks. */
  if (flags & BTC_BLOCK_VERIFY_BODY) {
    int64_t now = btc_timedata_now(chain->timedata);
    btc_verify_error_t err;

    if (!btc_block_check_sanity(&err, block, now)) {
      if (!err.malleated)
        btc_chain_set_invalid(chain, hash);

      return btc_chain_throw(chain, hdr,
                             BTC_REJECT_INVALID,
                             err.reason,
                             err.score,
                             err.malleated);
    }
  }

  /* Prevent orphan and alternate chain attacks. */
  if (!btc_chain_check_target(chain, hdr))
    return 0;

  /* Find the previous block entry. */
  prev = btc_chaindb_by_hash(chain->db, hdr->prev_block);

  /* If previous block wasn't ever seen,
     add it current to orphans and return. */
  if (prev == NULL) {
    btc_chain_store_orphan(chain, block, id);
    return 1;
  }

  /* Connect the block. */
  entry = btc_chain_connect(chain, prev, block);

  if (entry == NULL)
    return 0;

  /* Handle any orphans. */
  if (btc_chain_has_next_orphan(chain, hash))
    btc_chain_handle_orphans(chain, entry);

  return 1;
}

const btc_entry_t *
btc_chain_tip(btc_chain_t *chain) {
  return chain->tip;
}

int32_t
btc_chain_height(btc_chain_t *chain) {
  return chain->height;
}

const btc_deployment_state_t *
btc_chain_state(btc_chain_t *chain) {
  return &chain->state;
}

const btc_verify_error_t *
btc_chain_error(btc_chain_t *chain) {
  return &chain->error;
}

double
btc_chain_progress(btc_chain_t *chain) {
  int64_t now = btc_timedata_now(chain->timedata);
  int64_t start = chain->network->genesis.header.time;
  int64_t current = chain->tip->header.time - start;
  int64_t end = (now - start) - 40 * 60;
  double progress;

  if (end < 1)
    end = 1;

  progress = (double)current / (double)end;

  if (progress > 1.0)
    progress = 1.0;

  return progress;
}

size_t
btc_chain_orphans(btc_chain_t *chain) {
  return chain->orphan_map.size;
}

int
btc_chain_synced(btc_chain_t *chain) {
  return chain->synced;
}

int
btc_chain_pruned(btc_chain_t *chain) {
  return (chain->flags & BTC_CHAIN_PRUNE) != 0;
}

int
btc_chain_has_hash(btc_chain_t *chain, const uint8_t *hash) {
  return btc_chaindb_by_hash(chain->db, hash) != NULL;
}

const btc_entry_t *
btc_chain_by_hash(btc_chain_t *chain, const uint8_t *hash) {
  return btc_chaindb_by_hash(chain->db, hash);
}

const btc_entry_t *
btc_chain_by_height(btc_chain_t *chain, int32_t height) {
  return btc_chaindb_by_height(chain->db, height);
}

int
btc_chain_is_main(btc_chain_t *chain, const btc_entry_t *entry) {
  return btc_chaindb_is_main(chain->db, entry);
}

int
btc_chain_has_coins(btc_chain_t *chain, const btc_tx_t *tx) {
  return btc_chaindb_has_coins(chain->db, tx);
}

btc_coin_t *
btc_chain_coin(btc_chain_t *chain, const uint8_t *hash, size_t index) {
  return btc_chaindb_coin(chain->db, hash, index);
}

int
btc_chain_get_coins(btc_chain_t *chain,
                    btc_view_t *view,
                    const btc_tx_t *tx) {
  return btc_chaindb_fill(chain->db, view, tx);
}

btc_block_t *
btc_chain_get_block(btc_chain_t *chain, const btc_entry_t *entry) {
  return btc_chaindb_get_block(chain->db, entry);
}

int
btc_chain_get_raw_block(btc_chain_t *chain,
                        uint8_t **data,
                        size_t *length,
                        const btc_entry_t *entry) {
  return btc_chaindb_get_raw_block(chain->db, data, length, entry);
}

btc_view_t *
btc_chain_get_undo(btc_chain_t *chain,
                   const btc_entry_t *entry,
                   const btc_block_t *block) {
  return btc_chaindb_get_undo(chain->db, entry, block);
}

const uint8_t *
btc_chain_get_orphan_root(btc_chain_t *chain, const uint8_t *hash) {
  const uint8_t *root = NULL;
  btc_orphan_t *orphan;

  for (;;) {
    orphan = btc_hashmap_get(&chain->orphan_map, hash);

    if (orphan == NULL)
      break;

    root = hash;
    hash = orphan->block->header.prev_block;
  }

  return root;
}

void
btc_chain_get_locator(btc_chain_t *chain,
                      btc_vector_t *hashes,
                      const uint8_t *start) {
  const btc_entry_t *entry = chain->tip;
  int32_t step = 1;
  int32_t height;

  CHECK(hashes->length == 0);

  if (start != NULL) {
    entry = btc_chaindb_by_hash(chain->db, start);

    CHECK(entry != NULL);
  }

  btc_vector_push(hashes, entry->hash);

  height = entry->height;

  while (height > 0) {
    height -= step;

    if (height < 0)
      height = 0;

    if (hashes->length > 10)
      step *= 2;

    entry = btc_chain_get_ancestor(chain, entry, height);

    CHECK(entry != NULL);

    btc_vector_push(hashes, entry->hash);
  }
}

const btc_entry_t *
btc_chain_find_locator(btc_chain_t *chain, const btc_vector_t *locator) {
  const btc_entry_t *entry;
  size_t i;

  for (i = 0; i < locator->length; i++) {
    entry = btc_chaindb_by_hash(chain->db, locator->items[i]);

    if (entry == NULL)
      continue;

    if (btc_chaindb_is_main(chain->db, entry))
      return entry;
  }

  return btc_chaindb_head(chain->db);
}

uint32_t
btc_chain_compute_version(btc_chain_t *chain, const btc_entry_t *prev) {
  const btc_network_t *network = chain->network;
  const btc_deployment_t *deploy;
  uint32_t version = 0;
  int state;
  size_t i;

  for (i = 0; i < network->deployments.length; i++) {
    deploy = &network->deployments.items[i];
    state = btc_chain_get_state(chain, prev, deploy);

    if (state == BTC_STATE_LOCKED_IN || state == BTC_STATE_STARTED)
      version |= (UINT32_C(1) << deploy->bit);
  }

  version |= BTC_VERSION_TOP_BITS;

  return version;
}
