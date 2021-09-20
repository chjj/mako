/*!
 * chain.c - chain for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <lmdb.h>

#include <node/chain.h>
#include <node/chaindb.h>
#include <node/logger.h>
#include <node/timedata.h>

#include <satoshi/block.h>
#include <satoshi/coins.h>
#include <satoshi/consensus.h>
#include <satoshi/crypto/hash.h>
#include <satoshi/entry.h>
#include <satoshi/header.h>
#include <satoshi/mpi.h>
#include <satoshi/network.h>
#include <satoshi/script.h>
#include <satoshi/tx.h>
#include <satoshi/util.h>
#include <satoshi/vector.h>

#include "../map.h"
#include "../impl.h"
#include "../internal.h"
#include "io.h"

/*
 * Deployment State
 */

static void
btc_deployment_state_init(btc_deployment_state_t *state) {
  memset(state, 0, sizeof(*state));

  state->flags = BTC_SCRIPT_MANDATORY_VERIFY_FLAGS;
  state->flags &= ~BTC_SCRIPT_VERIFY_P2SH;
  state->lock_flags = BTC_CHAIN_MANDATORY_LOCKTIME_FLAGS;
  state->bip34 = 0;
  state->bip91 = 0;
  state->bip148 = 0;
}

/*
 * Orphan Block
 */

typedef struct btc_orphan_s {
  uint8_t hash[32];
  btc_block_t *block;
  unsigned int flags;
  int id;
  int64_t time;
} btc_orphan_t;

DEFINE_OBJECT(btc_orphan, SCOPE_STATIC)

void
btc_orphan_init(btc_orphan_t *orphan) {
  memset(orphan, 0, sizeof(*orphan));
}

void
btc_orphan_clear(btc_orphan_t *orphan) {
  if (orphan->block != NULL)
    btc_block_destroy(orphan->block);

  orphan->block = NULL;
}

void
btc_orphan_copy(btc_orphan_t *z, const btc_orphan_t *x) {
  *z = *x;
}

/*
 * Chain
 */

KHASH_SET_INIT_HASH(invalid)
KHASH_MAP_INIT_CONST_HASH(orphans, btc_orphan_t *)

struct btc_chain_s {
  const btc_network_t *network;
  btc_logger_t *logger;
  btc_chaindb_t *db;
  const btc_timedata_t *timedata;
  khash_t(invalid) *invalid;
  khash_t(orphans) *orphan_map;
  khash_t(orphans) *orphan_prev;
  btc_entry_t *tip;
  int32_t height;
  btc_deployment_state_t state;
  btc_verify_error_t error;
  int synced;
  btc_connect_cb *on_connect;
  btc_connect_cb *on_disconnect;
  btc_reorganize_cb *on_reorganize;
  btc_badorphan_cb *on_badorphan;
  void *arg;
  int checkpoints_enabled;
  int bip91_enabled;
  int bip148_enabled;
};

struct btc_chain_s *
btc_chain_create(const btc_network_t *network) {
  struct btc_chain_s *chain =
    (struct btc_chain_s *)btc_malloc(sizeof(struct btc_chain_s));

  memset(chain, 0, sizeof(*chain));

  chain->network = network;
  chain->logger = NULL;
  chain->db = btc_chaindb_create(network);
  chain->timedata = NULL;
  chain->invalid = kh_init(invalid);
  chain->orphan_map = kh_init(orphans);
  chain->orphan_prev = kh_init(orphans);
  chain->tip = NULL;
  chain->height = -1;

  CHECK(chain->invalid != NULL);
  CHECK(chain->orphan_map != NULL);
  CHECK(chain->orphan_prev != NULL);

  btc_deployment_state_init(&chain->state);

  return chain;
}

void
btc_chain_destroy(struct btc_chain_s *chain) {
  khiter_t it = kh_begin(chain->invalid);

  for (; it != kh_end(chain->invalid); it++) {
    if (kh_exist(chain->invalid, it))
      btc_free(kh_key(chain->invalid, it));
  }

  it = kh_begin(chain->orphan_map);

  for (; it != kh_end(chain->orphan_map); it++) {
    if (kh_exist(chain->orphan_map, it))
      btc_orphan_destroy(kh_value(chain->orphan_map, it));
  }

  kh_destroy(invalid, chain->invalid);
  kh_destroy(orphans, chain->orphan_map);
  kh_destroy(orphans, chain->orphan_prev);

  btc_chaindb_destroy(chain->db);

  btc_free(chain);
}

void
btc_chain_set_logger(struct btc_chain_s *chain, btc_logger_t *logger) {
  chain->logger = logger;
}

void
btc_chain_set_timedata(struct btc_chain_s *chain, const btc_timedata_t *td) {
  chain->timedata = td;
}

void
btc_chain_on_connect(struct btc_chain_s *chain, btc_connect_cb *handler) {
  chain->on_connect = handler;
}

void
btc_chain_on_disconnect(struct btc_chain_s *chain, btc_connect_cb *handler) {
  chain->on_disconnect = handler;
}

void
btc_chain_on_reorganize(struct btc_chain_s *chain, btc_reorganize_cb *handler) {
  chain->on_reorganize = handler;
}

void
btc_chain_on_badorphan(struct btc_chain_s *chain, btc_badorphan_cb *handler) {
  chain->on_badorphan = handler;
}

void
btc_chain_set_context(struct btc_chain_s *chain, void *arg) {
  chain->arg = arg;
}

void
btc_chain_set_checkpoints(struct btc_chain_s *chain, int value) {
  chain->checkpoints_enabled = value;
}

static void
btc_chain_log(struct btc_chain_s *chain, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  btc_logger_write(chain->logger, "chain", fmt, ap);
  va_end(ap);
}

static void
btc_chain_get_deployment_state(struct btc_chain_s *chain,
                               btc_deployment_state_t *state);

int
btc_chain_open(struct btc_chain_s *chain, const char *prefix, size_t map_size) {
  btc_chain_log(chain, "Chain is loading.");

  if (chain->checkpoints_enabled)
    btc_chain_log(chain, "Checkpoints are enabled.");

  if (!btc_chaindb_open(chain->db, prefix, map_size))
    return 0;

  chain->tip = (btc_entry_t *)btc_chaindb_tail(chain->db);
  chain->height = chain->tip->height;

  btc_chain_get_deployment_state(chain, &chain->state);

  btc_chain_log(chain, "Chain Height: %d", chain->height);

  return 1;
}

void
btc_chain_close(struct btc_chain_s *chain) {
  btc_chaindb_close(chain->db);
}

static int64_t
btc_chain_now(struct btc_chain_s *chain) {
  if (chain->timedata == NULL)
    return btc_now();

  return btc_timedata_now(chain->timedata);
}

static void
btc_chain_add_orphan(struct btc_chain_s *chain, btc_orphan_t *orphan) {
  btc_header_t *hdr = &orphan->block->header;
  int ret = -1;
  khiter_t it;

  it = kh_put(orphans, chain->orphan_map, orphan->hash, &ret);

  CHECK(ret > 0);

  kh_value(chain->orphan_map, it) = orphan;

  it = kh_put(orphans, chain->orphan_prev, hdr->prev_block, &ret);

  CHECK(ret > 0);

  kh_value(chain->orphan_prev, it) = orphan;
}

static void
btc_chain_remove_orphan(struct btc_chain_s *chain, const btc_orphan_t *orphan) {
  const btc_header_t *hdr = &orphan->block->header;
  khiter_t it;

  it = kh_get(orphans, chain->orphan_map, orphan->hash);

  CHECK(it != kh_end(chain->orphan_map));

  kh_del(orphans, chain->orphan_map, it);

  it = kh_get(orphans, chain->orphan_prev, hdr->prev_block);

  CHECK(it != kh_end(chain->orphan_prev));

  kh_del(orphans, chain->orphan_prev, it);
}

int
btc_chain_has_orphan(struct btc_chain_s *chain, const uint8_t *hash) {
  khiter_t it = kh_get(orphans, chain->orphan_map, hash);
  return it != kh_end(chain->orphan_map);
}

static void
btc_chain_limit_orphans(struct btc_chain_s *chain) {
  btc_orphan_t *oldest = NULL;
  btc_orphan_t *orphan;
  btc_vector_t orphans;
  khiter_t it;
  size_t i;

  if (kh_size(chain->orphan_map) <= 20)
    return;

  btc_vector_init(&orphans);

  it = kh_begin(chain->orphan_map);

  for (; it != kh_end(chain->orphan_map); it++) {
    if (!kh_exist(chain->orphan_map, it))
      continue;

    orphan = kh_value(chain->orphan_map, it);

    if (oldest == NULL || orphan->time < oldest->time)
      oldest = orphan;

    btc_vector_push(&orphans, orphan);
  }

  for (i = 0; i < orphans.length; i++) {
    orphan = (btc_orphan_t *)orphans.items[i];

    if (orphan == oldest)
      continue;

    btc_chain_remove_orphan(chain, orphan);
    btc_orphan_destroy(orphan);
  }

  btc_vector_clear(&orphans);
}

static void
btc_chain_purge_orphans(struct btc_chain_s *chain) {
  size_t count = kh_size(chain->orphan_map);
  khiter_t it;

  if (count == 0)
    return;

  it = kh_begin(chain->orphan_map);

  for (; it != kh_end(chain->orphan_map); it++) {
    if (kh_exist(chain->orphan_map, it))
      btc_orphan_destroy(kh_value(chain->orphan_map, it));
  }

  kh_clear(orphans, chain->orphan_map);
  kh_clear(orphans, chain->orphan_prev);

  btc_chain_log(chain, "Purged %zu orphans.", count);
}

static btc_orphan_t *
btc_chain_resolve_orphan(struct btc_chain_s *chain, const uint8_t *hash) {
  khiter_t it = kh_get(orphans, chain->orphan_prev, hash);
  btc_orphan_t *orphan;

  if (it == kh_end(chain->orphan_prev))
    return NULL;

  orphan = kh_value(chain->orphan_prev, it);

  btc_chain_remove_orphan(chain, orphan);

  return orphan;
}

static void
btc_chain_store_orphan(struct btc_chain_s *chain,
                       const btc_block_t *block,
                       unsigned int flags,
                       int id) {
  const btc_header_t *hdr = &block->header;
  int32_t height = btc_block_coinbase_height(block);
  btc_orphan_t *orphan;
  khiter_t it;

  it = kh_get(orphans, chain->orphan_prev, hdr->prev_block);

  /* The orphan chain forked. */
  if (it != kh_end(chain->orphan_prev)) {
    orphan = kh_value(chain->orphan_prev, it);

    btc_chain_log(chain,
      "Removing forked orphan block: %H (%d).",
      orphan->hash, height);

    btc_chain_remove_orphan(chain, orphan);
    btc_orphan_destroy(orphan);

    return;
  }

  orphan = btc_orphan_create();
  orphan->block = btc_block_clone(block);
  orphan->flags = flags;
  orphan->id = id;
  orphan->time = btc_now();

  btc_header_hash(orphan->hash, hdr);

  btc_chain_limit_orphans(chain);
  btc_chain_add_orphan(chain, orphan);

  btc_chain_log(chain,
    "Storing orphan block: %H (%d).",
    orphan->hash, height);
}

static int
btc_chain_has_next_orphan(struct btc_chain_s *chain, const uint8_t *hash) {
  khiter_t it = kh_get(orphans, chain->orphan_prev, hash);
  return it != kh_end(chain->orphan_prev);
}

static void
btc_chain_set_invalid(struct btc_chain_s *chain, const uint8_t *hash) {
  int ret = -1;
  khiter_t it;

  it = kh_put(invalid, chain->invalid, (uint8_t *)hash, &ret);

  CHECK(ret != -1);

  if (ret == 0)
    return;

  kh_key(chain->invalid, it) = btc_hash_clone(hash);
}

BTC_UNUSED static void
btc_chain_remove_invalid(struct btc_chain_s *chain, const uint8_t *hash) {
  khiter_t it = kh_get(invalid, chain->invalid, (uint8_t *)hash);

  if (it == kh_end(chain->invalid))
    return;

  btc_free(kh_key(chain->invalid, it));

  kh_del(invalid, chain->invalid, it);
}

static int
btc_chain_has_invalid(struct btc_chain_s *chain, const uint8_t *hash) {
  khiter_t it = kh_get(invalid, chain->invalid, (uint8_t *)hash);
  return it != kh_end(chain->invalid);
}

static int
btc_chain_is_invalid(struct btc_chain_s *chain, const btc_block_t *block) {
  const btc_header_t *hdr = &block->header;
  uint8_t hash[32];
  khiter_t it;

  btc_header_hash(hash, hdr);

  it = kh_get(invalid, chain->invalid, hash);

  if (it != kh_end(chain->invalid))
    return 1;

  it = kh_get(invalid, chain->invalid, (uint8_t *)hdr->prev_block);

  if (it != kh_end(chain->invalid)) {
    btc_chain_set_invalid(chain, hash);
    return 1;
  }

  return 0;
}

static int
btc_chain_verify_checkpoint(struct btc_chain_s *chain,
                            const btc_entry_t *prev,
                            const uint8_t *hash) {
  const btc_network_t *network = chain->network;
  int32_t height = prev->height + 1;
  const btc_checkpoint_t *chk;

  if (!chain->checkpoints_enabled)
    return 1;

  chk = btc_network_checkpoint(network, height);

  if (chk == NULL)
    return 1;

  if (btc_hash_equal(hash, chk->hash)) {
    btc_chain_log(chain, "Hit checkpoint block %H (%d).", hash, height);
    return 1;
  }

  /* Someone is either mining on top of
     an old block for no reason, or the
     consensus protocol is broken and
     there was a 20k+ block reorg. */
  btc_chain_log(chain,
    "Checkpoint mismatch at height %d: expected=%H received=%H",
    height,
    chk->hash,
    hash
  );

  btc_chain_purge_orphans(chain);

  return 0;
}

static int
btc_chain_is_historical(struct btc_chain_s *chain, const btc_entry_t *prev) {
  if (chain->checkpoints_enabled) {
    if (prev->height + 1 <= chain->network->last_checkpoint)
      return 1;
  }

  return 0;
}

static const btc_entry_t *
btc_chain_get_ancestor(struct btc_chain_s *chain,
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
btc_chain_retarget(struct btc_chain_s *chain,
                   const btc_entry_t *prev,
                   const btc_entry_t *first) {
  const btc_network_t *net = chain->network;
  int64_t target_timespan = net->pow.target_timespan;
  int64_t actual_timespan;
  mpz_t limit, target;
  uint32_t ret;

  if (net->pow.no_retargeting)
    return prev->header.bits;

  mpz_init(limit);
  mpz_import(limit, net->pow.limit, 32, -1);

  mpz_init_set_compact(target, prev->header.bits);

  actual_timespan = prev->header.time - first->header.time;

  if (actual_timespan < target_timespan / 4)
    actual_timespan = target_timespan / 4;

  if (actual_timespan > target_timespan * 4)
    actual_timespan = target_timespan * 4;

  mpz_mul_ui(target, target, actual_timespan);
  mpz_quo_ui(target, target, target_timespan);

  if (mpz_cmp(target, limit) <= 0)
    ret = mpz_get_compact(target);
  else
    ret = net->pow.bits;

  btc_chain_log(chain, "Retargeting to: %#.8x.", ret);

  mpz_clear(limit);
  mpz_clear(target);

  return ret;
}

uint32_t
btc_chain_get_target(struct btc_chain_s *chain,
                     int64_t time,
                     const btc_entry_t *prev) {
  const btc_network_t *net = chain->network;
  const btc_entry_t *first;
  int32_t height;

  if (prev == NULL) {
    CHECK(time == net->genesis.header.time);
    return net->pow.bits;
  }

  /* Do not retarget. */
  if ((prev->height + 1) % net->pow.retarget_interval != 0) {
    if (net->pow.target_reset) {
      /* Special behavior for testnet. */
      if (time > prev->header.time + net->pow.target_spacing * 2)
        return net->pow.bits;

      while (prev->prev != NULL
             && prev->height % net->pow.retarget_interval != 0
             && prev->header.bits == net->pow.bits) {
        prev = prev->prev;
      }
    }

    return prev->header.bits;
  }

  /* Back 2 weeks. */
  height = prev->height - (net->pow.retarget_interval - 1);

  CHECK(height >= 0);

  first = btc_chain_get_ancestor(chain, prev, height);

  CHECK(first != NULL);

  return btc_chain_retarget(chain, prev, first);
}

uint32_t
btc_chain_get_current_target(struct btc_chain_s *chain) {
  return btc_chain_get_target(chain, btc_chain_now(chain), chain->tip);
}

static int
btc_chain_get_state(struct btc_chain_s *chain,
                    const btc_entry_t *prev,
                    const btc_deployment_t *deployment) {
  int32_t threshold = chain->network->activation_threshold;
  int32_t window = chain->network->miner_window;
  const btc_entry_t *entry, *block;
  int bit = deployment->bit;
  btc_vector_t compute;
  int32_t height, count;
  int64_t time;
  int i, state;

  if (deployment->threshold != -1)
    threshold = deployment->threshold;

  if (deployment->window != -1)
    window = deployment->window;

  if (((prev->height + 1) % window) != 0) {
    height = prev->height - ((prev->height + 1) % window);
    prev = btc_chain_get_ancestor(chain, prev, height);

    if (prev == NULL)
      return BTC_CHAIN_DEFINED;

    CHECK(prev->height == height);
    CHECK(((prev->height + 1) % window) == 0);
  }

  entry = prev;
  state = BTC_CHAIN_DEFINED;

  btc_vector_init(&compute);

  while (entry != NULL) {
    time = btc_entry_median_time(entry);

    if (time < deployment->start_time) {
      state = BTC_CHAIN_DEFINED;
      break;
    }

    btc_vector_push(&compute, (void *)entry);

    height = entry->height - window;

    entry = btc_chain_get_ancestor(chain, entry, height);
  }

  while (compute.length > 0) {
    entry = (const btc_entry_t *)btc_vector_pop(&compute);

    switch (state) {
      case BTC_CHAIN_DEFINED: {
        time = btc_entry_median_time(entry);

        if (time >= deployment->timeout) {
          state = BTC_CHAIN_FAILED;
          break;
        }

        if (time >= deployment->start_time) {
          state = BTC_CHAIN_STARTED;
          break;
        }

        break;
      }

      case BTC_CHAIN_STARTED: {
        time = btc_entry_median_time(entry);

        if (time >= deployment->timeout) {
          state = BTC_CHAIN_FAILED;
          break;
        }

        block = entry;
        count = 0;

        for (i = 0; i < window; i++) {
          if (btc_has_versionbit(block->header.version, bit))
            count++;

          if (count >= threshold) {
            state = BTC_CHAIN_LOCKED_IN;
            break;
          }

          block = block->prev;

          CHECK(block != NULL);
        }

        break;
      }

      case BTC_CHAIN_LOCKED_IN: {
        state = BTC_CHAIN_ACTIVE;
        break;
      }

      case BTC_CHAIN_FAILED:
      case BTC_CHAIN_ACTIVE: {
        break;
      }

      default: {
        btc_abort(); /* LCOV_EXCL_LINE */
        break;
      }
    }
  }

  btc_vector_clear(&compute);

  return state;
}

static int
btc_chain_is_active(struct btc_chain_s *chain,
                    const btc_entry_t *prev,
                    const btc_deployment_t *deployment) {
  return btc_chain_get_state(chain, prev, deployment) == BTC_CHAIN_ACTIVE;
}

static void
btc_chain_get_deployments(struct btc_chain_s *chain,
                          btc_deployment_state_t *state,
                          int64_t time,
                          const btc_entry_t *prev) {
  const btc_network_t *network = chain->network;
  int32_t height = prev->height + 1;
  const btc_deployment_t *deploy;
  int witness;

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

  if (btc_chain_is_active(chain, prev, deploy)) {
    state->flags |= BTC_SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;
    state->lock_flags |= BTC_CHAIN_VERIFY_SEQUENCE;
    state->lock_flags |= BTC_CHAIN_MEDIAN_TIME_PAST;
  }

  /* Check the state of the segwit deployment. */
  deploy = btc_network_deployment(network, "segwit");
  witness = btc_chain_get_state(chain, prev, deploy);

  /* Segregrated witness (bip141) is now usable.
     along with SCRIPT_VERIFY_NULLDUMMY (bip147). */
  if (witness == BTC_CHAIN_ACTIVE) {
    state->flags |= BTC_SCRIPT_VERIFY_WITNESS;
    state->flags |= BTC_SCRIPT_VERIFY_NULLDUMMY;
  }

  /* Segsignal is now enforced (bip91). */
  if (chain->bip91_enabled) {
    if (witness == BTC_CHAIN_STARTED) {
      deploy = btc_network_deployment(network, "segsignal");

      if (btc_chain_is_active(chain, prev, deploy))
        state->bip91 = 1;
    }
  }

  /* UASF is now enforced (bip148) (mainnet-only). */
  if (chain->bip148_enabled && network->type == BTC_NETWORK_MAINNET) {
    if (witness != BTC_CHAIN_LOCKED_IN && witness != BTC_CHAIN_ACTIVE) {
      /* The BIP148 MTP check is nonsensical in
         that it includes the _current_ entry's
         timestamp. This requires some hackery,
         since we only operate on the sane
         assumption that deployment checks should
         only ever examine the values of the
         previous block (necessary for mining). */
      int64_t mtp = btc_entry_bip148_time(prev, time);

      if (mtp >= 1501545600 && mtp <= 1510704000)
        state->bip148 = 1;
    }
  }
}

static void
btc_chain_get_deployment_state(struct btc_chain_s *chain,
                               btc_deployment_state_t *state) {
  const btc_entry_t *tip = chain->tip;
  const btc_entry_t *prev = tip->prev;

  if (prev == NULL) {
    CHECK(tip->height == 0);
    btc_deployment_state_init(state);
    return;
  }

  btc_chain_get_deployments(chain, state, tip->header.time, prev);
}

static int
btc_chain_throw(struct btc_chain_s *chain,
                const btc_header_t *header,
                const char *code,
                const char *reason,
                int score,
                int malleated) {
  uint8_t *hash = chain->error.hash;

  btc_header_hash(hash, header);

  chain->error.code = code;
  chain->error.reason = reason;
  chain->error.score = score;
  chain->error.malleated = malleated;

  btc_chain_log(chain, "Verification error: %s "
                       "(code=%s score=%d hash=%H)",
                reason, code, score, hash);

  return 0;
}

static int
btc_chain_verify(struct btc_chain_s *chain,
                 btc_deployment_state_t *state,
                 const btc_block_t *block,
                 const btc_entry_t *prev,
                 unsigned int flags) {
  const btc_header_t *hdr = &block->header;
  const btc_network_t *network = chain->network;
  uint8_t hash[32];
  uint8_t root[32];
  int64_t time, mtp;
  int32_t height;
  int has_commit;
  uint32_t bits;
  size_t i;

  btc_deployment_state_init(state);

  /* Extra sanity check. */
  if (!btc_hash_equal(hdr->prev_block, prev->hash))
    return btc_chain_throw(chain, hdr, "invalid", "bad-prevblk", 0, 0);

  /* Verify a checkpoint if there is one. */
  btc_header_hash(hash, hdr);

  if (!btc_chain_verify_checkpoint(chain, prev, hash)) {
    return btc_chain_throw(chain, hdr,
                           "checkpoint",
                           "checkpoint mismatch",
                           100,
                           0);
  }

  /* Skip everything when using checkpoints.
     We can do this safely because every
     block in between each checkpoint was
     validated outside in the header chain. */
  if (btc_chain_is_historical(chain, prev)) {
    /* Check merkle root. */
    if (flags & BTC_CHAIN_VERIFY_BODY) {
      int rc = btc_block_merkle_root(root, block);

      if (rc == 0 || !btc_hash_equal(hdr->merkle_root, root)) {
        return btc_chain_throw(chain, hdr,
                               "invalid",
                               "bad-txnmrklroot",
                               100,
                               1);
      }

      flags &= ~BTC_CHAIN_VERIFY_BODY;
    }

    /* Once segwit is active, we will still
       need to check for block mutability. */
    if (!btc_block_has_witness(block)) {
      if (!btc_block_get_commitment_hash(root, block)) {
        btc_deployment_state_init(state);
        return 1;
      }
    }
  }

  /* Non-contextual checks. */
  if (flags & BTC_CHAIN_VERIFY_BODY) {
    btc_verify_error_t err;

    if (!btc_block_check_body(&err, block))
      return btc_chain_throw(chain, hdr, "invalid", err.reason, err.score, 1);
  }

  /* Ensure the POW is what we expect. */
  bits = btc_chain_get_target(chain, hdr->time, prev);

  if (hdr->bits != bits)
    return btc_chain_throw(chain, hdr, "invalid", "bad-diffbits", 100, 0);

  /* Ensure the timestamp is correct. */
  mtp = btc_entry_median_time(prev);

  if (hdr->time <= mtp)
    return btc_chain_throw(chain, hdr, "invalid", "time-too-old", 0, 0);

  /* Check timestamp against adjtime+2hours.
     If this fails we may be able to accept
     the block later. */
  if (hdr->time > btc_chain_now(chain) + 2 * 60 * 60)
    return btc_chain_throw(chain, hdr, "invalid", "time-too-new", 0, 1);

  /* Calculate height of current block. */
  height = prev->height + 1;

  /* Only allow version 2 blocks (coinbase height)
     once the majority of blocks are using it. */
  if (hdr->version < 2 && height >= network->softforks.bip34.height)
    return btc_chain_throw(chain, hdr, "obsolete", "bad-version", 0, 0);

  /* Only allow version 3 blocks (sig validation)
     once the majority of blocks are using it. */
  if (hdr->version < 3 && height >= network->softforks.bip66.height)
    return btc_chain_throw(chain, hdr, "obsolete", "bad-version", 0, 0);

  /* Only allow version 4 blocks (checklocktimeverify)
     once the majority of blocks are using it. */
  if (hdr->version < 4 && height >= network->softforks.bip65.height)
    return btc_chain_throw(chain, hdr, "obsolete", "bad-version", 0, 0);

  /* Get the new deployment state. */
  btc_chain_get_deployments(chain, state, hdr->time, prev);

  /* Enforce BIP91/BIP148. */
  if (state->bip91 || state->bip148) {
    const btc_deployment_t *segwit = btc_network_deployment(network, "segwit");

    if (!btc_has_versionbit(hdr->version, segwit->bit))
      return btc_chain_throw(chain, hdr, "invalid", "bad-no-segwit", 0, 0);
  }

  /* Get timestamp for tx.isFinal(). */
  time = hdr->time;

  if (state->lock_flags & BTC_CHAIN_MEDIAN_TIME_PAST)
    time = mtp;

  /* Transactions must be finalized with
     regards to nSequence and nLockTime. */
  for (i = 0; i < block->txs.length; i++) {
    const btc_tx_t *tx = block->txs.items[i];

    if (!btc_tx_is_final(tx, height, time))
      return btc_chain_throw(chain, hdr, "invalid", "bad-txns-nonfinal", 10, 0);
  }

  /* Make sure the height contained
     in the coinbase is correct. */
  if (state->bip34) {
    if (btc_block_coinbase_height(block) != height)
      return btc_chain_throw(chain, hdr, "invalid", "bad-cb-height", 100, 0);
  }

  /* Check the commitment hash for segwit. */
  has_commit = 0;

  if (state->flags & BTC_SCRIPT_VERIFY_WITNESS) {
    if (btc_block_get_commitment_hash(hash, block)) {
      /* These are totally malleable. Someone
         may have even accidentally sent us
         the non-witness version of the block.
         We don't want to consider this block
         "invalid" if either of these checks
         fail. */
      if (!btc_block_witness_nonce(block)) {
        return btc_chain_throw(chain, hdr,
                               "invalid",
                               "bad-witness-nonce-size",
                               100,
                               1);
      }

      CHECK(btc_block_create_commitment_hash(root, block));

      if (!btc_hash_equal(hash, root)) {
        return btc_chain_throw(chain, hdr,
                               "invalid",
                               "bad-witness-merkle-match",
                               100,
                               1);
      }

      has_commit = 1;
    }
  }

  /* Blocks that do not commit to
     witness data cannot contain it. */
  if (!has_commit) {
    if (btc_block_has_witness(block)) {
      return btc_chain_throw(chain, hdr,
                             "invalid",
                             "unexpected-witness",
                             100,
                             1);
    }
  }

  /* Check block weight (different from block size
     check in non-contextual verification). */
  if (btc_block_weight(block) > BTC_MAX_BLOCK_WEIGHT) {
    return btc_chain_throw(chain, hdr,
                           "invalid",
                           "bad-blk-weight",
                           100,
                           0);
  }

  return 1;
}

static int
btc_chain_verify_duplicates(struct btc_chain_s *chain,
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
  const btc_checkpoint_t *chk;
  const btc_tx_t *tx;
  uint8_t hash[32];
  size_t i;

  btc_header_hash(hash, hdr);

  for (i = 0; i < block->txs.length; i++) {
    tx = block->txs.items[i];

    if (!btc_chaindb_has_coins(chain->db, tx))
      continue;

    chk = btc_network_bip30(network, prev->height + 1);

    /* Blocks 91842 and 91880 created duplicate
       txids by using the same exact output script
       and extraNonce. */
    if (chk == NULL || !btc_hash_equal(hash, chk->hash)) {
      return btc_chain_throw(chain, hdr,
                             "invalid",
                             "bad-txns-BIP30",
                             100,
                             0);
    }
  }

  return 1;
}

static btc_view_t *
btc_chain_update_inputs(struct btc_chain_s *chain,
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
btc_chain_verify_final(struct btc_chain_s *chain,
                       const btc_entry_t *prev,
                       const btc_tx_t *tx,
                       unsigned int flags) {
  int32_t height = prev->height + 1;

  /* We can skip MTP if the locktime is height. */
  if (tx->locktime < BTC_LOCKTIME_THRESHOLD)
    return btc_tx_is_final(tx, height, -1);

  if (flags & BTC_CHAIN_MEDIAN_TIME_PAST) {
    int64_t ts = btc_entry_median_time(prev);
    return btc_tx_is_final(tx, height, ts);
  }

  return btc_tx_is_final(tx, height, btc_chain_now(chain));
}

int
btc_chain_verify_locks(struct btc_chain_s *chain,
                       const btc_entry_t *prev,
                       const btc_tx_t *tx,
                       btc_view_t *view,
                       unsigned int flags) {
  int32_t min_height = -1;
  int64_t min_time = -1;
  size_t i;

  if (!(flags & BTC_CHAIN_VERIFY_SEQUENCE))
    return 1;

  if (btc_tx_is_coinbase(tx) || tx->version < 2)
    return 1;

  for (i = 0; i < tx->inputs.length; i++) {
    const btc_input_t *input = tx->inputs.items[i];
    uint32_t sequence = input->sequence;
    const btc_entry_t *entry;
    const btc_coin_t *coin;
    int32_t height;
    int64_t time;

    if (sequence & BTC_SEQUENCE_DISABLE_FLAG)
      continue;

    coin = btc_view_get(view, &input->prevout);

    if (coin == NULL || coin->height == -1)
      height = chain->height + 1;
    else
      height = coin->height;

    if (!(sequence & BTC_SEQUENCE_TYPE_FLAG)) {
      height += (sequence & BTC_SEQUENCE_MASK) - 1;

      if (height > min_height)
        min_height = height;

      continue;
    }

    if (height > 0)
      height -= 1;

    entry = btc_chain_get_ancestor(chain, prev, height);

    CHECK(entry != NULL);

    time = btc_entry_median_time(entry);

    time += ((sequence & BTC_SEQUENCE_MASK) << BTC_SEQUENCE_GRANULARITY) - 1;

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
btc_chain_verify_inputs(struct btc_chain_s *chain,
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
                        "invalid",
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
                        "invalid",
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
                      "invalid",
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
                        "invalid",
                        err.reason,
                        err.score,
                        0);
        goto fail;
      }

      reward += fee;

      if (reward < 0 || reward > BTC_MAX_MONEY) {
        btc_chain_throw(chain, hdr,
                        "invalid",
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
                    "invalid",
                    "bad-cb-amount",
                    100,
                    0);
    goto fail;
  }

  /* Verify all transactions. */
  for (i = 1; i < block->txs.length; i++) {
    const btc_tx_t *tx = block->txs.items[i];

    if (!btc_tx_verify(tx, view, state->flags)) {
      btc_chain_throw(chain, hdr,
                      "invalid",
                      "mandatory-script-verify-flag-failed",
                      100,
                      0);
      goto fail;
    }
  }

  return view;
fail:
  btc_view_destroy(view);
  return NULL;
}

static btc_view_t *
btc_chain_verify_context(struct btc_chain_s *chain,
                         btc_deployment_state_t *state,
                         const btc_block_t *block,
                         const btc_entry_t *prev,
                         unsigned int flags) {
  /* Initial non-contextual verification. */
  if (!btc_chain_verify(chain, state, block, prev, flags))
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
btc_chain_reconnect(struct btc_chain_s *chain, btc_entry_t *entry) {
  const btc_header_t *hdr = &entry->header;
  unsigned int flags = BTC_CHAIN_VERIFY_NONE;
  btc_deployment_state_t state;
  btc_entry_t *prev;
  btc_block_t *block;
  btc_view_t *view;
  int ret = 0;

  block = btc_chaindb_get_block(chain->db, entry);

  if (block == NULL) {
    btc_chain_log(chain, "Block data not found: %H (%d).",
                         entry->hash, entry->height);

    return btc_chain_throw(chain, hdr,
                           "internal",
                           "block-data-not-found",
                           0,
                           1);
  }

  prev = entry->prev;

  CHECK(prev != NULL);

  view = btc_chain_verify_context(chain, &state, block, prev, flags);

  if (view == NULL) {
    if (!chain->error.malleated)
      btc_chain_set_invalid(chain, entry->hash);

    btc_chain_log(chain, "Tried to connect invalid block: %H (%d).",
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
btc_chain_disconnect(struct btc_chain_s *chain, btc_entry_t *entry) {
  const btc_header_t *hdr = &entry->header;
  btc_entry_t *prev;
  btc_block_t *block;
  btc_view_t *view;

  block = btc_chaindb_get_block(chain->db, entry);

  if (block == NULL) {
    btc_chain_log(chain, "Block data not found: %H (%d).",
                         entry->hash, entry->height);

    return btc_chain_throw(chain, hdr,
                           "internal",
                           "block-data-not-found",
                           0,
                           1);
  }

  prev = entry->prev;

  CHECK(prev != NULL);

  view = btc_chaindb_disconnect(chain->db, entry, block);

  CHECK(view != NULL);

  chain->tip = prev;
  chain->height = prev->height;

  if (chain->on_disconnect != NULL)
    chain->on_disconnect(entry, block, view, chain->arg);

  btc_view_destroy(view);
  btc_block_destroy(block);

  return 1;
}

static void
btc_chain_unreorganize(struct btc_chain_s *chain,
                       const btc_entry_t *fork,
                       btc_entry_t *last) {
  btc_entry_t *tip = chain->tip;
  btc_vector_t disconnect, connect;
  btc_entry_t *entry;
  size_t i;

  btc_vector_init(&disconnect);
  btc_vector_init(&connect);

  /* Blocks to disconnect. */
  for (entry = tip; entry != fork; entry = entry->prev) {
    btc_vector_push(&disconnect, entry);
    entry = entry->prev;
  }

  /* Blocks to connect. */
  for (entry = last; entry != fork; entry = entry->prev) {
    btc_vector_push(&connect, entry);
    entry = entry->prev;
  }

  /* Disconnect blocks and transactions. */
  for (i = 0; i < disconnect.length; i++) {
    entry = (btc_entry_t *)disconnect.items[i];

    CHECK(btc_chain_disconnect(chain, entry));
  }

  /* Connect blocks and transactions. */
  for (i = connect.length - 1; i != (size_t)-1; i--) {
    entry = (btc_entry_t *)connect.items[i];

    CHECK(btc_chain_reconnect(chain, entry));
  }

  btc_chain_log(chain,
    "Chain un-reorganization: old=%H(%d) new=%H(%d)",
    tip->hash,
    tip->height,
    last->hash,
    last->height
  );

  if (chain->on_reorganize != NULL)
    chain->on_reorganize(tip, last, chain->arg);

  btc_vector_clear(&disconnect);
  btc_vector_clear(&connect);
}

static const btc_entry_t *
find_fork(const btc_entry_t *fork, const btc_entry_t *longer) {
  while (fork != longer) {
    while (longer->height > fork->height) {
      longer = longer->prev;

      CHECK(longer != NULL);
    }

    if (fork == longer)
      return fork;

    fork = fork->prev;

    CHECK(fork != NULL);
  }

  return fork;
}

static const btc_entry_t *
btc_chain_reorganize(struct btc_chain_s *chain, btc_entry_t *competitor) {
  btc_entry_t *tip = chain->tip;
  btc_vector_t disconnect, connect;
  const btc_entry_t *fork;
  btc_entry_t *entry;
  size_t i;

  btc_vector_init(&disconnect);
  btc_vector_init(&connect);

  fork = find_fork(tip, competitor);

  /* Blocks to disconnect. */
  for (entry = tip; entry != fork; entry = entry->prev) {
    btc_vector_push(&disconnect, entry);
    entry = entry->prev;
  }

  /* Blocks to connect. */
  for (entry = competitor; entry != fork; entry = entry->prev) {
    btc_vector_push(&connect, entry);
    entry = entry->prev;
  }

  /* Disconnect blocks and transactions. */
  for (i = 0; i < disconnect.length; i++) {
    entry = (btc_entry_t *)disconnect.items[i];

    CHECK(btc_chain_disconnect(chain, entry));
  }

  /* Sanity check. */
  CHECK(connect.length > 0);

  /* Connect blocks and transactions. Note that
     we don't want to connect the new tip here.
     That will be done outside in set_best_chain. */
  for (i = connect.length - 1; i != 0; i--) {
    entry = (btc_entry_t *)connect.items[i];

    if (!btc_chain_reconnect(chain, entry)) {
      if (!chain->error.malleated) {
        while (i--) {
          entry = (btc_entry_t *)connect.items[i];
          btc_chain_set_invalid(chain, entry->hash);
        }
      }

      if (btc_hash_compare(chain->tip->chainwork, tip->chainwork) < 0)
        btc_chain_unreorganize(chain, fork, tip);

      fork = NULL;
      goto done;
    }
  }

  btc_chain_log(chain,
    "Chain reorganization: old=%H(%d) new=%H(%d)",
    tip->hash,
    tip->height,
    competitor->hash,
    competitor->height
  );

  if (chain->on_reorganize != NULL)
    chain->on_reorganize(tip, competitor, chain->arg);

done:
  btc_vector_clear(&disconnect);
  btc_vector_clear(&connect);
  return fork;
}

static int
btc_chain_save_alternate(struct btc_chain_s *chain,
                         btc_entry_t *entry,
                         const btc_block_t *block,
                         unsigned int flags) {
  const btc_header_t *hdr = &block->header;
  btc_deployment_state_t state;

  /* Do not accept forked chain older than the last checkpoint. */
  if (chain->checkpoints_enabled) {
    if (entry->height < chain->network->last_checkpoint) {
      return btc_chain_throw(chain, hdr,
                             "checkpoint",
                             "bad-fork-prior-to-checkpoint",
                             100,
                             0);
    }
  }

  /* Do as much verification as we can before saving. */
  if (!btc_chain_verify(chain, &state, block, entry->prev, flags)) {
    if (!chain->error.malleated)
      btc_chain_set_invalid(chain, entry->hash);

    btc_chain_log(chain, "Invalid block on alternate chain: %H (%d).",
                         entry->hash, entry->height);

    return 0;
  }

  CHECK(btc_chaindb_save(chain->db, entry, block, NULL));

  btc_chain_log(chain, "Heads up: Competing chain at height %d:"
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
btc_chain_set_best_chain(struct btc_chain_s *chain,
                         btc_entry_t *entry,
                         const btc_block_t *block,
                         unsigned int flags) {
  const btc_entry_t *fork = NULL;
  btc_entry_t *tip = chain->tip;
  btc_deployment_state_t state;
  btc_view_t *view;

  /* A higher fork has arrived. Time to reorganize the chain. */
  if (!btc_hash_equal(entry->header.prev_block, tip->hash)) {
    /* Do as much verification as we can before reorganizing. */
    if (!btc_chain_verify(chain, &state, block, entry->prev, flags)) {
      if (!chain->error.malleated)
        btc_chain_set_invalid(chain, entry->hash);

      btc_chain_log(chain, "Tried to connect invalid block: %H (%d).",
                           entry->hash, entry->height);

      return 0;
    }

    btc_chain_log(chain, "WARNING: Reorganizing chain.");

    fork = btc_chain_reorganize(chain, entry);

    if (fork == NULL)
      return 0;
  }

  /* Otherwise, everything is in order. Do "contextual" verification
     on our block now that we're certain its previous block is in
     the chain. */
  view = btc_chain_verify_context(chain, &state, block, entry->prev, flags);

  if (view == NULL) {
    if (!chain->error.malleated)
      btc_chain_set_invalid(chain, entry->hash);

    btc_chain_log(chain, "Tried to connect invalid block: %H (%d).",
                         entry->hash, entry->height);

    if (fork != NULL) {
      if (btc_hash_compare(chain->tip->chainwork, tip->chainwork) < 0)
        btc_chain_unreorganize(chain, fork, tip);
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

  btc_view_destroy(view);

  return 1;
}

static const btc_entry_t *
btc_chain_connect(struct btc_chain_s *chain,
                  const btc_entry_t *prev,
                  const btc_block_t *block,
                  unsigned int flags) {
  const btc_header_t *hdr = &block->header;
  btc_entry_t *entry = btc_entry_create();

  /* Sanity check. */
  CHECK(btc_hash_equal(hdr->prev_block, prev->hash));

  /* Create a new chain entry. */
  btc_entry_set_block(entry, block, prev);

  /* The block is on a alternate chain if the chainwork
     is less than or equal to our tip's. Add the block
     but do _not_ connect the inputs. */
  if (btc_hash_compare(entry->chainwork, chain->tip->chainwork) <= 0) {
    /* Save block to an alternate chain. */
    if (!btc_chain_save_alternate(chain, entry, block, flags)) {
      btc_entry_destroy(entry);
      return NULL;
    }
  } else {
    /* Attempt to add block to the chain index. */
    if (!btc_chain_set_best_chain(chain, entry, block, flags)) {
      btc_entry_destroy(entry);
      return NULL;
    }
  }

  btc_chain_log(chain, "Block %H (%d) added to chain (txs=%zu).",
                entry->hash,
                entry->height,
                block->txs.length);

  return entry;
}

static void
btc_chain_handle_orphans(struct btc_chain_s *chain, const btc_entry_t *entry) {
  btc_orphan_t *orphan = btc_chain_resolve_orphan(chain, entry->hash);

  while (orphan != NULL) {
    entry = btc_chain_connect(chain, entry, orphan->block, orphan->flags);

    btc_orphan_destroy(orphan);

    if (entry == NULL) {
      btc_chain_log(chain,
        "Could not resolve orphan block %H: %s.",
        orphan->hash, chain->error.reason);

      if (chain->on_badorphan != NULL)
        chain->on_badorphan(&chain->error, orphan->id, chain->arg);

      break;
    }

    btc_chain_log(chain,
      "Orphan block was resolved: %H (%d).",
      entry->hash, entry->height);

    orphan = btc_chain_resolve_orphan(chain, entry->hash);
  }
}

int
btc_chain_add(struct btc_chain_s *chain,
              const btc_block_t *block,
              unsigned int flags,
              int id) {
  const btc_network_t *network = chain->network;
  const btc_header_t *hdr = &block->header;
  const btc_entry_t *prev, *entry;
  uint8_t hash[32];

  btc_header_hash(hash, hdr);

  /* Special case for genesis block. */
  if (btc_hash_equal(hash, network->genesis.hash)) {
    btc_chain_log(chain, "Saw genesis block: %H.", hash);
    return btc_chain_throw(chain, hdr, "duplicate", "duplicate", 0, 0);
  }

  /* If the block is already known to be
     an orphan, ignore it. */
  if (btc_chain_has_orphan(chain, hash)) {
    btc_chain_log(chain, "Already have orphan block: %H.", hash);
    return btc_chain_throw(chain, hdr, "duplicate", "duplicate", 0, 0);
  }

  /* Do not revalidate known invalid blocks. */
  if (btc_chain_is_invalid(chain, block)) {
    btc_chain_log(chain, "Invalid ancestors for block: %H.", hash);
    return btc_chain_throw(chain, hdr, "duplicate", "duplicate", 100, 0);
  }

  /* Check the PoW before doing anything. */
  if (flags & BTC_CHAIN_VERIFY_POW) {
    if (!btc_header_verify(hdr))
      return btc_chain_throw(chain, hdr, "invalid", "high-hash", 50, 0);
  }

  /* Do we already have this block? */
  if (btc_chaindb_by_hash(chain->db, hash) != NULL) {
    btc_chain_log(chain, "Already have block: %H.", hash);
    return btc_chain_throw(chain, hdr, "duplicate", "duplicate", 0, 0);
  }

  /* Find the previous block entry. */
  prev = btc_chaindb_by_hash(chain->db, hdr->prev_block);

  /* If previous block wasn't ever seen,
     add it current to orphans and return. */
  if (prev == NULL) {
    btc_chain_store_orphan(chain, block, flags, id);
    return 1;
  }

  /* Connect the block. */
  entry = btc_chain_connect(chain, prev, block, flags);

  if (entry == NULL)
    return 0;

  /* Handle any orphans. */
  if (btc_chain_has_next_orphan(chain, hash))
    btc_chain_handle_orphans(chain, entry);

  return 1;
}

const btc_entry_t *
btc_chain_tip(struct btc_chain_s *chain) {
  return chain->tip;
}

int32_t
btc_chain_height(struct btc_chain_s *chain) {
  return chain->height;
}

const btc_deployment_state_t *
btc_chain_state(struct btc_chain_s *chain) {
  return &chain->state;
}

const btc_verify_error_t *
btc_chain_error(struct btc_chain_s *chain) {
  return &chain->error;
}

int
btc_chain_synced(struct btc_chain_s *chain) {
  return chain->synced;
}

const btc_entry_t *
btc_chain_by_hash(struct btc_chain_s *chain, const uint8_t *hash) {
  return btc_chaindb_by_hash(chain->db, hash);
}

const btc_entry_t *
btc_chain_by_height(struct btc_chain_s *chain, int32_t height) {
  return btc_chaindb_by_height(chain->db, height);
}

int
btc_chain_is_main(btc_chain_t *chain, const btc_entry_t *entry) {
  return btc_chaindb_is_main(chain->db, entry);
}

int
btc_chain_has_coins(struct btc_chain_s *chain, const btc_tx_t *tx) {
  return btc_chaindb_has_coins(chain->db, tx);
}

int
btc_chain_get_coins(struct btc_chain_s *chain,
                    btc_view_t *view,
                    const btc_tx_t *tx) {
  return btc_chaindb_fill(chain->db, view, tx);
}

btc_block_t *
btc_chain_get_block(struct btc_chain_s *chain, const btc_entry_t *entry) {
  return btc_chaindb_get_block(chain->db, entry);
}

int
btc_chain_get_raw_block(struct btc_chain_s *chain,
                        uint8_t **data,
                        size_t *length,
                        const btc_entry_t *entry) {
  return btc_chaindb_get_raw_block(chain->db, data, length, entry);
}

int
btc_chain_has(struct btc_chain_s *chain, const uint8_t *hash) {
  if (btc_chain_has_orphan(chain, hash))
    return 1;

  if (btc_chain_has_invalid(chain, hash))
    return 1;

  return btc_chaindb_by_hash(chain->db, hash) != NULL;
}

const uint8_t *
btc_chain_get_orphan_root(struct btc_chain_s *chain, const uint8_t *hash) {
  const uint8_t *root = NULL;
  btc_orphan_t *orphan;
  khiter_t it;

  for (;;) {
    it = kh_get(orphans, chain->orphan_map, hash);

    if (it == kh_end(chain->orphan_map))
      break;

    orphan = kh_value(chain->orphan_map, it);

    root = hash;
    hash = orphan->block->header.prev_block;
  }

  return root;
}

void
btc_chain_get_locator(struct btc_chain_s *chain,
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

  btc_vector_push(hashes, (void *)entry->hash);

  height = entry->height;

  while (height > 0) {
    height -= step;

    if (height < 0)
      height = 0;

    if (hashes->length > 10)
      step *= 2;

    entry = btc_chain_get_ancestor(chain, entry, height);

    CHECK(entry != NULL);

    btc_vector_push(hashes, (void *)entry->hash);
  }
}

const btc_entry_t *
btc_chain_find_locator(struct btc_chain_s *chain, const btc_vector_t *locator) {
  const btc_entry_t *entry;
  const uint8_t *hash;
  size_t i;

  for (i = 0; i < locator->length; i++) {
    hash = (const uint8_t *)locator->items[i];
    entry = btc_chaindb_by_hash(chain->db, hash);

    if (entry == NULL)
      continue;

    if (btc_chaindb_is_main(chain->db, entry))
      return entry;
  }

  return btc_chaindb_head(chain->db);
}
