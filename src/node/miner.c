/*!
 * miner.c - miner for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <io/core.h>
#include <io/loop.h>

#include <node/chain.h>
#include <base/logger.h>
#include <node/mempool.h>
#include <node/miner.h>
#include <base/timedata.h>

#include <mako/address.h>
#include <mako/block.h>
#include <mako/buffer.h>
#include <mako/coins.h>
#include <mako/consensus.h>
#include <mako/crypto/hash.h>
#include <mako/crypto/merkle.h>
#include <mako/crypto/rand.h>
#include <mako/entry.h>
#include <mako/header.h>
#include <mako/heap.h>
#include <mako/map.h>
#include <mako/net.h>
#include <mako/netaddr.h>
#include <mako/netmsg.h>
#include <mako/network.h>
#include <mako/policy.h>
#include <mako/script.h>
#include <mako/tx.h>
#include <mako/util.h>
#include <mako/vector.h>

#include "../bio.h"
#include "../impl.h"
#include "../internal.h"

/*
 * Constants
 */

static const uint8_t zero_nonce[32] = {0};
static const uint8_t default_flags[] = "mined by mako";

/*
 * Types
 */

struct btc_cpuminer_s;

typedef struct btc_cputhread_s {
  struct btc_cpuminer_s *cpu;
  uint32_t nonce1;
  uint32_t nonce2;
  /* Protected by cpu.lock. */
  int64_t time;
  uint32_t nonce;
  uint8_t root[32];
  int result;
} btc_cputhread_t;

typedef struct btc_cpuminer_s {
  btc_miner_t *miner;
  int mining;
  int64_t last_check;
  btc_mutex_t lock;
  btc_cond_t master;
  btc_cond_t worker;
  btc_cputhread_t *threads;
  int length;
  uint8_t last_tip[32];
  int64_t last_job;
  /* Protected by cpu.lock. */
  btc_tmpl_t *job;
  int active;
  int stop;
} btc_cpuminer_t;

struct btc_miner_s {
  const btc_network_t *network;
  btc_loop_t *loop;
  btc_logger_t *logger;
  const btc_timedata_t *timedata;
  btc_chain_t *chain;
  btc_mempool_t *mempool;
  unsigned int flags;
  btc_buffer_t cbflags;
  btc_vector_t addrs;
  btc_cpuminer_t cpu;
};

BTC_DEFINE_LOGGER(btc_log, btc_miner_t, "miner")

/*
 * Block Entry
 */

DEFINE_OBJECT(btc_blockentry, SCOPE_STATIC)

static void
btc_blockentry_init(btc_blockentry_t *entry) {
  memset(entry, 0, sizeof(*entry));
}

static void
btc_blockentry_clear(btc_blockentry_t *entry) {
  if (entry->tx != NULL)
    btc_tx_destroy(entry->tx);

  entry->tx = NULL;
}

static void
btc_blockentry_copy(btc_blockentry_t *z, const btc_blockentry_t *x) {
  (void)z;
  (void)x;
  btc_abort(); /* LCOV_EXCL_LINE */
}

static void
btc_blockentry_set_tx(btc_blockentry_t *z, const btc_tx_t *x) {
  z->tx = btc_tx_clone(x);
  z->hash = z->tx->hash;
  z->whash = z->tx->whash;
  z->fee = 0;
  z->rate = 0;
  z->weight = btc_tx_weight(x);
  z->sigops = 0;
  z->desc_rate = 0;
  z->dep_count = 0;
}

static void
btc_blockentry_set_view(btc_blockentry_t *z,
                        const btc_tx_t *x,
                        const btc_view_t *view) {
  int sigops = btc_tx_sigops_cost(x, view, BTC_SCRIPT_STANDARD_VERIFY_FLAGS);
  size_t size = btc_tx_sigops_size(x, sigops);

  z->tx = btc_tx_clone(x);
  z->hash = z->tx->hash;
  z->whash = z->tx->whash;
  z->fee = btc_tx_fee(x, view);
  z->rate = btc_get_rate(z->fee, size);
  z->weight = btc_tx_weight(x);
  z->sigops = sigops;
  z->desc_rate = z->rate;
  z->dep_count = 0;
}

static void
btc_blockentry_set_mpentry(btc_blockentry_t *z, const btc_mpentry_t *x) {
  z->tx = btc_tx_ref(x->tx);
  z->hash = z->tx->hash;
  z->whash = z->tx->whash;
  z->fee = x->fee;
  z->rate = btc_get_rate(x->delta_fee, x->size);
  z->weight = btc_tx_weight(x->tx);
  z->sigops = x->sigops;
  z->desc_rate = btc_get_rate(x->desc_fee, x->desc_size);
  z->dep_count = 0;
}

/*
 * Merkle Steps
 */

static void
btc_steps_init(btc_steps_t *steps) {
  memset(steps, 0, sizeof(*steps));
}

static void
btc_steps_push(btc_steps_t *steps, const uint8_t *step) {
  CHECK(steps->length * 32 < sizeof(steps->hashes));

  memcpy(&steps->hashes[steps->length * 32], step, 32);

  steps->length++;
}

static void
btc_steps_compute(btc_steps_t *steps, uint8_t *nodes, size_t size) {
  uint8_t *left, *right, *last;
  size_t i;

  btc_steps_init(steps);

  while (size > 1) {
    btc_steps_push(steps, &nodes[1 * 32]);

    memset(&nodes[0 * 32], 0, 32);

    for (i = 2; i < size; i += 2) {
      left = &nodes[(i + 0) * 32];
      right = left;

      if (i + 1 < size)
        right = &nodes[(i + 1) * 32];

      last = &nodes[(i / 2) * 32];

      btc_hash256_root(last, left, right);
    }

    size = (size + 1) / 2;
  }
}

static void
btc_steps_root(uint8_t *root, const btc_steps_t *steps, const uint8_t *hash) {
  size_t i;

  memcpy(root, hash, 32);

  for (i = 0; i < steps->length; i++)
    btc_hash256_root(root, root, &steps->hashes[i * 32]);
}

/*
 * Block Template
 */

DEFINE_OBJECT(btc_tmpl, SCOPE_EXTERN)

void
btc_tmpl_init(btc_tmpl_t *bt) {
  memset(bt, 0, sizeof(*bt));

  bt->version = BTC_VERSION_TOP_BITS;
  bt->time = btc_now();
  bt->bits = 0x207fffff;
  bt->mtp = bt->time - 10 * 60;
  bt->flags = BTC_SCRIPT_STANDARD_VERIFY_FLAGS;
  bt->interval = 210000;
  bt->weight = 4000;
  bt->sigops = 400;
  bt->chain_nonce = btc_random();

  btc_steps_init(&bt->steps);
  btc_buffer_init(&bt->cbflags);
  btc_address_init(&bt->address);
  btc_vector_init(&bt->txs);

  btc_buffer_set(&bt->cbflags, default_flags, sizeof(default_flags) - 1);
}

void
btc_tmpl_clear(btc_tmpl_t *bt) {
  size_t i;

  for (i = 0; i < bt->txs.length; i++)
    btc_blockentry_destroy(bt->txs.items[i]);

  btc_buffer_clear(&bt->cbflags);
  btc_vector_clear(&bt->txs);
}

void
btc_tmpl_copy(btc_tmpl_t *z, const btc_tmpl_t *x) {
  (void)z;
  (void)x;
  btc_abort(); /* LCOV_EXCL_LINE */
}

int64_t
btc_tmpl_reward(const btc_tmpl_t *bt) {
  int64_t reward = btc_get_reward(bt->height, bt->interval);
  return reward + bt->fees;
}

int
btc_tmpl_witness(const btc_tmpl_t *bt) {
  return (bt->flags & BTC_SCRIPT_VERIFY_WITNESS) != 0;
}

int64_t
btc_tmpl_locktime(const btc_tmpl_t *bt) {
  if (bt->flags & BTC_SCRIPT_VERIFY_CHECKSEQUENCEVERIFY)
    return bt->mtp;

  return bt->time;
}

static void
btc_tmpl_precompute(btc_steps_t *steps, btc_tmpl_t *bt) {
  size_t length = bt->txs.length + 1;
  uint8_t *hashes = (uint8_t *)btc_malloc(length * 32);
  size_t i;

  btc_hash_init(&hashes[0 * 32]);

  for (i = 0; i < bt->txs.length; i++) {
    const btc_blockentry_t *entry = bt->txs.items[i];

    btc_hash_copy(&hashes[(i + 1) * 32], entry->hash);
  }

  btc_steps_compute(steps, hashes, length);

  btc_free(hashes);
}

static void
btc_tmpl_witness_hash(uint8_t *hash, const btc_tmpl_t *bt) {
  size_t length = bt->txs.length + 1;
  uint8_t *hashes = (uint8_t *)btc_malloc(length * 32);
  uint8_t root[32];
  size_t i;

  btc_hash_init(&hashes[0 * 32]);

  for (i = 0; i < bt->txs.length; i++) {
    const btc_blockentry_t *entry = bt->txs.items[i];

    btc_hash_copy(&hashes[(i + 1) * 32], entry->whash);
  }

  CHECK(btc_merkle_root(root, hashes, length));

  btc_free(hashes);

  btc_hash256_root(hash, root, zero_nonce);
}

void
btc_tmpl_refresh(btc_tmpl_t *bt) {
  btc_tmpl_witness_hash(bt->commitment, bt);
  btc_tmpl_precompute(&bt->steps, bt);
}

btc_tx_t *
btc_tmpl_coinbase(const btc_tmpl_t *bt, uint32_t nonce1, uint32_t nonce2) {
  btc_tx_t *tx = btc_tx_create();
  btc_writer_t writer;
  btc_input_t *input;
  btc_output_t *output;
  uint8_t height_raw[9];
  uint8_t nonce_raw[4];
  uint8_t extra_raw[8];

  btc_writer_init(&writer);

  /* Coinbase input. */
  input = btc_input_create();

  /* Height (required in v2+ blocks) */
  btc_writer_push_num(&writer, bt->height, height_raw);

  /* Coinbase flags. */
  CHECK(bt->cbflags.length <= 70);
  btc_writer_push_data(&writer, bt->cbflags.data,
                                bt->cbflags.length);

  /* Smaller nonce for good measure. */
  btc_uint32_write(nonce_raw, bt->chain_nonce);
  btc_writer_push_data(&writer, nonce_raw, 4);

  /* Extra nonce: incremented when the nonce overflows. */
  btc_write32be(extra_raw + 0, nonce1);
  btc_write32be(extra_raw + 4, nonce2);
  btc_writer_push_data(&writer, extra_raw, 8);

  /* Compile. */
  btc_writer_compile(&input->script, &writer);

  /* Set up the witness nonce. */
  if (bt->flags & BTC_SCRIPT_VERIFY_WITNESS)
    btc_stack_push_data(&input->witness, zero_nonce, 32);

  btc_inpvec_push(&tx->inputs, input);

  /* Reward output. */
  output = btc_output_create();

  btc_address_get_script(&output->script, &bt->address);

  output->value = btc_tmpl_reward(bt);

  btc_outvec_push(&tx->outputs, output);

  /* If we're using segwit, we need to set up the commitment. */
  if (bt->flags & BTC_SCRIPT_VERIFY_WITNESS) {
    /* Commitment output. */
    output = btc_output_create();

    btc_script_set_commitment(&output->script, bt->commitment);

    btc_outvec_push(&tx->outputs, output);
  }

  btc_tx_refresh(tx);

  CHECK(input->script.length <= 100);

  btc_writer_clear(&writer);

  return tx;
}

void
btc_tmpl_compute(uint8_t *root, const btc_tmpl_t *bt, const uint8_t *hash) {
  btc_steps_root(root, &bt->steps, hash);
}

void
btc_tmpl_root(uint8_t *root,
              const btc_tmpl_t *bt,
              uint32_t nonce1,
              uint32_t nonce2) {
  btc_tx_t *cb = btc_tmpl_coinbase(bt, nonce1, nonce2);

  btc_tmpl_compute(root, bt, cb->hash);

  btc_tx_destroy(cb);
}

void
btc_tmpl_header(btc_header_t *hdr,
                const btc_tmpl_t *bt,
                const uint8_t *root,
                int64_t time,
                uint32_t nonce) {
  hdr->version = bt->version;
  btc_hash_copy(hdr->prev_block, bt->prev_block);
  btc_hash_copy(hdr->merkle_root, root);
  hdr->time = time;
  hdr->bits = bt->bits;
  hdr->nonce = nonce;
}

int
btc_tmpl_prove(btc_blockproof_t *proof,
               const btc_tmpl_t *bt,
               uint32_t nonce1,
               uint32_t nonce2,
               int64_t time,
               uint32_t nonce) {
  uint8_t target[32];
  btc_header_t hdr;

  btc_tmpl_root(proof->root, bt, nonce1, nonce2);
  btc_tmpl_header(&hdr, bt, proof->root, time, nonce);
  btc_header_hash(proof->hash, &hdr);

  proof->nonce1 = nonce1;
  proof->nonce2 = nonce2;
  proof->time = time;
  proof->nonce = nonce;

  CHECK(btc_compact_export(target, bt->bits));

  return btc_hash_compare(proof->hash, target) <= 0;
}

btc_block_t *
btc_tmpl_commit(const btc_tmpl_t *bt, const btc_blockproof_t *proof) {
  btc_tx_t *cb = btc_tmpl_coinbase(bt, proof->nonce1, proof->nonce2);
  btc_block_t *block = btc_block_create();
  btc_header_t *hdr = &block->header;
  size_t i;

  hdr->version = bt->version;
  btc_hash_copy(hdr->prev_block, bt->prev_block);
  btc_hash_copy(hdr->merkle_root, proof->root);
  hdr->time = proof->time;
  hdr->bits = bt->bits;
  hdr->nonce = proof->nonce;

  btc_txvec_push(&block->txs, cb);

  for (i = 0; i < bt->txs.length; i++) {
    const btc_blockentry_t *item = bt->txs.items[i];

    btc_txvec_push(&block->txs, btc_tx_ref(item->tx));
  }

  return block;
}

void
btc_tmpl_getwork(btc_header_t *hdr,
                 const btc_tmpl_t *bt,
                 uint32_t nonce1,
                 uint32_t nonce2) {
  uint8_t root[32];

  btc_tmpl_root(root, bt, nonce1, nonce2);
  btc_tmpl_header(hdr, bt, root, bt->time, 0);
}

btc_block_t *
btc_tmpl_submitwork(const btc_tmpl_t *bt,
                    const btc_header_t *hdr,
                    uint32_t nonce1,
                    uint32_t nonce2) {
  btc_block_t *block;
  uint8_t root[32];
  btc_tx_t *cb;
  size_t i;

  if (hdr->version != bt->version)
    return NULL;

  if (!btc_hash_equal(hdr->prev_block, bt->prev_block))
    return NULL;

  if (hdr->time <= bt->mtp)
    return NULL;

  if (hdr->time > bt->time + 2 * 60 * 60)
    return NULL;

  if (hdr->bits != bt->bits)
    return NULL;

  if (!btc_header_verify(hdr))
    return NULL;

  cb = btc_tmpl_coinbase(bt, nonce1, nonce2);

  btc_tmpl_compute(root, bt, cb->hash);

  if (!btc_hash_equal(hdr->merkle_root, root)) {
    btc_tx_destroy(cb);
    return NULL;
  }

  block = btc_block_create();

  btc_header_copy(&block->header, hdr);
  btc_txvec_push(&block->txs, cb);

  for (i = 0; i < bt->txs.length; i++) {
    const btc_blockentry_t *item = bt->txs.items[i];

    btc_txvec_push(&block->txs, btc_tx_ref(item->tx));
  }

  return block;
}

btc_block_t *
btc_tmpl_mine(const btc_tmpl_t *bt) {
  /* Simple mining function for testing.
     This function will run until it
     finds a block: i.e. do not call
     on mainnet. */
  uint32_t nonce2 = (uint32_t)-1;
  btc_block_t *block;
  btc_header_t hdr;

  do {
    btc_tmpl_getwork(&hdr, bt, 0, ++nonce2);
  } while (!btc_header_mine(&hdr, 0));

  block = btc_tmpl_submitwork(bt, &hdr, 0, nonce2);

  CHECK(block != NULL);

  return block;
}

void
btc_tmpl_push(btc_tmpl_t *bt, const btc_tx_t *tx, const btc_view_t *view) {
  btc_blockentry_t *item = btc_blockentry_create();

  if (view != NULL)
    btc_blockentry_set_view(item, tx, view);
  else
    btc_blockentry_set_tx(item, tx);

  bt->weight += item->weight;
  bt->sigops += item->sigops;
  bt->fees += item->fee;

  btc_vector_push(&bt->txs, item);
}

int
btc_tmpl_add(btc_tmpl_t *bt, const btc_tx_t *tx, const btc_view_t *view) {
  btc_blockentry_t *item = btc_blockentry_create();

  if (view != NULL)
    btc_blockentry_set_view(item, tx, view);
  else
    btc_blockentry_set_tx(item, tx);

  if (bt->flags & BTC_SCRIPT_VERIFY_CHECKSEQUENCEVERIFY) {
    if (!btc_tx_is_final(tx, bt->height, bt->mtp))
      goto fail;
  } else {
    if (!btc_tx_is_final(tx, bt->height, bt->time))
      goto fail;
  }

  if (!(bt->flags & BTC_SCRIPT_VERIFY_WITNESS)) {
    if (btc_tx_has_witness(tx))
      goto fail;
  }

  if (bt->weight + item->weight > BTC_MAX_BLOCK_WEIGHT)
    goto fail;

  if (bt->sigops + item->sigops > BTC_MAX_BLOCK_SIGOPS_COST)
    goto fail;

  bt->weight += item->weight;
  bt->sigops += item->sigops;
  bt->fees += item->fee;

  btc_vector_push(&bt->txs, item);

  return 1;
fail:
  btc_blockentry_destroy(item);
  return 0;
}

/*
 * CPU Miner
 */

static void
btc_cpuminer_init(btc_cpuminer_t *cpu, btc_miner_t *miner, int length) {
  btc_cputhread_t *thread;
  int i;

  if (length < 1)
    length = 1;

  cpu->miner = miner;
  cpu->mining = 0;
  cpu->last_check = 0;

  btc_mutex_init(&cpu->lock);
  btc_cond_init(&cpu->master);
  btc_cond_init(&cpu->worker);

  cpu->threads = btc_malloc(length * sizeof(btc_cputhread_t));
  cpu->length = length;
  btc_hash_init(cpu->last_tip);
  cpu->last_job = 0;
  cpu->job = NULL;
  cpu->active = 0;
  cpu->stop = 0;

  for (i = 0; i < length; i++) {
    thread = &cpu->threads[i];

    memset(thread, 0, sizeof(*thread));

    thread->cpu = cpu;
    thread->result = -1;
  }
}

static void
btc_cpuminer_clear(btc_cpuminer_t *cpu) {
  btc_mutex_destroy(&cpu->lock);
  btc_cond_destroy(&cpu->master);
  btc_cond_destroy(&cpu->worker);
  btc_free(cpu->threads);
}

static void
btc_cpuminer_start_job(btc_cpuminer_t *cpu) {
  /* Must be called with lock held. */
  btc_cputhread_t *thread;
  int i;

  if (cpu->job != NULL)
    btc_tmpl_destroy(cpu->job);

  cpu->job = btc_miner_template(cpu->miner);

  btc_hash_copy(cpu->last_tip, cpu->job->prev_block);

  cpu->last_job = btc_time_msec();

  for (i = 0; i < cpu->length; i++) {
    thread = &cpu->threads[i];

    thread->nonce1 = UINT32_C(1) << (31 - i);
    thread->nonce2 = 0;
    thread->time = cpu->job->time;
    thread->nonce = 0;

    btc_tmpl_root(thread->root, cpu->job, thread->nonce1, 0);

    thread->result = -1;
  }
}

static void
btc_cpuminer_stop_job(btc_cpuminer_t *cpu) {
  /* Must be called with lock held. */
  btc_cputhread_t *thread;
  int i;

  if (cpu->job != NULL)
    btc_tmpl_destroy(cpu->job);

  cpu->job = NULL;

  for (i = 0; i < cpu->length; i++) {
    thread = &cpu->threads[i];

    thread->nonce1 = 0;
    thread->nonce2 = 0;
    thread->time = 0;
    thread->nonce = 0;

    btc_hash_init(thread->root);

    thread->result = -1;
  }
}

static void
on_tick(void *arg);

static void
mining_thread(void *arg);

static void
btc_cpuminer_start(btc_cpuminer_t *cpu, int active) {
  btc_miner_t *miner = cpu->miner;
  btc_thread_t thread;
  int i;

  btc_log_info(miner, "Starting miner.");

  if (active < 1)
    active = 1;

  if (active > cpu->length)
    active = cpu->length;

  CHECK(cpu->mining == 0);
  CHECK(cpu->active == 0);

  cpu->mining = 1;

  btc_loop_on_tick(miner->loop, on_tick, cpu);

  for (i = 0; i < active; i++) {
    btc_thread_create(&thread, mining_thread, &cpu->threads[i]);
    btc_thread_detach(&thread);
  }

  cpu->active = active;
}

static void
btc_cpuminer_stop(btc_cpuminer_t *cpu) {
  btc_miner_t *miner = cpu->miner;

  btc_log_info(miner, "Stopping miner...");

  CHECK(cpu->mining == 1);

  btc_mutex_lock(&cpu->lock);

  cpu->stop = 1;

  btc_cpuminer_stop_job(cpu);
  btc_hash_init(cpu->last_tip);

  btc_cond_signal(&cpu->worker);
  btc_mutex_unlock(&cpu->lock);

  btc_mutex_lock(&cpu->lock);

  while (cpu->active > 0)
    btc_cond_wait(&cpu->master, &cpu->lock);

  cpu->stop = 0;

  btc_mutex_unlock(&cpu->lock);

  cpu->mining = 0;

  btc_loop_off_tick(miner->loop, on_tick, cpu);

  btc_log_info(miner, "Miner stopped.");
}

static void
btc_cpuminer_setgenerate(btc_cpuminer_t *cpu, int value, int active) {
#if defined(_WIN32) || defined(BTC_PTHREAD)
  int mining = (value != 0);

  if (cpu->mining == mining)
    return;

  if (mining)
    btc_cpuminer_start(cpu, active);
  else
    btc_cpuminer_stop(cpu);
#else
  (void)cpu;
  (void)value;
  (void)active;
#endif
}

static void
on_tick(void *arg) {
  btc_cpuminer_t *cpu = arg;
  btc_miner_t *miner = cpu->miner;
  int64_t now = btc_time_msec();
  btc_cputhread_t *thread;
  const btc_entry_t *tip;
  btc_blockproof_t proof;
  btc_block_t *block;
  int i;

  CHECK(cpu->mining == 1);

  if (now < cpu->last_check + 250)
    return;

  cpu->last_check = now;

  btc_mutex_lock(&cpu->lock);

  /* Get tip for below checks. */
  tip = btc_chain_tip(miner->chain);

  /* Do we have a job? */
  if (cpu->job == NULL) {
    /* Is this a new tip? */
    if (!btc_hash_equal(cpu->last_tip, tip->hash)) {
      /* Start a new job. */
      btc_cpuminer_start_job(cpu);
      btc_cond_broadcast(&cpu->worker);
    }
    goto done;
  }

  for (i = 0; i < cpu->length; i++) {
    thread = &cpu->threads[i];

    /* Did we find a block? */
    if (thread->result == 1) {
      CHECK(btc_tmpl_prove(&proof,
                           cpu->job,
                           thread->nonce1,
                           thread->nonce2,
                           thread->time,
                           thread->nonce));

      block = btc_tmpl_commit(cpu->job, &proof);

      if (!btc_hash_equal(cpu->job->prev_block, tip->hash)) {
        /* Job is stale. Start new job immediately. */
        btc_cpuminer_start_job(cpu);
        btc_cond_broadcast(&cpu->worker);
      } else {
        /* Wait for new job. */
        btc_cpuminer_stop_job(cpu);
      }

      btc_mutex_unlock(&cpu->lock);

      CHECK(btc_chain_add(miner->chain, block, BTC_BLOCK_DEFAULT_FLAGS, 0));

      btc_block_destroy(block);

      return;
    }
  }

  /* Is our job stale? */
  if (!btc_hash_equal(cpu->job->prev_block, tip->hash)) {
    btc_cpuminer_start_job(cpu);
    btc_cond_broadcast(&cpu->worker);
    goto done;
  }

  /* Do we need to check the mempool again? */
  if (now >= cpu->last_job + 60 * 1000) {
    btc_cpuminer_start_job(cpu);
    btc_cond_broadcast(&cpu->worker);
    goto done;
  }

  now = btc_timedata_now(miner->timedata);

  for (i = 0; i < cpu->length; i++) {
    thread = &cpu->threads[i];

    /* Are we still working? */
    if (thread->result == -1)
      continue;

    /* Update timestamp if possible. */
    if (now > thread->time) {
      thread->nonce = 0;
      thread->time = now;
      thread->result = -1;
      continue;
    }

    /* Increment extra nonce. */
    if (thread->nonce >= (UINT32_C(1) << 31)) {
      thread->nonce1 += (++thread->nonce2 == 0);
      thread->nonce = 0;

      btc_tmpl_root(thread->root,
                    cpu->job,
                    thread->nonce1,
                    thread->nonce2);

      thread->result = -1;

      continue;
    }

    thread->result = -1;
  }

  btc_cond_broadcast(&cpu->worker);

done:
  btc_mutex_unlock(&cpu->lock);
}

static void
mining_thread(void *arg) {
  btc_cputhread_t *thread = arg;
  btc_cpuminer_t *cpu = thread->cpu;
  btc_header_t hdr;
  int result = -1;

  for (;;) {
    btc_mutex_lock(&cpu->lock);

    CHECK(thread->result == -1);

    if (!cpu->stop && result != -1) {
      thread->result = result;
      thread->nonce = hdr.nonce;
    }

    while (!cpu->stop) {
      if (cpu->job != NULL && thread->result == -1)
        break;

      btc_cond_wait(&cpu->worker, &cpu->lock);
    }

    if (cpu->stop)
      break;

    btc_tmpl_header(&hdr, cpu->job,
                          thread->root,
                          thread->time,
                          thread->nonce);

    btc_mutex_unlock(&cpu->lock);

    result = btc_header_mine(&hdr, 3 << 20);
  }

  if (--cpu->active == 0)
    btc_cond_signal(&cpu->master);

  btc_mutex_unlock(&cpu->lock);
}

/*
 * Miner
 */

btc_miner_t *
btc_miner_create(const btc_network_t *network,
                 btc_loop_t *loop,
                 btc_chain_t *chain,
                 btc_mempool_t *mempool) {
  btc_miner_t *miner = (btc_miner_t *)btc_malloc(sizeof(btc_miner_t));

  memset(miner, 0, sizeof(*miner));

  miner->network = network;
  miner->loop = loop;
  miner->logger = NULL;
  miner->timedata = NULL;
  miner->chain = chain;
  miner->mempool = mempool;
  miner->flags = BTC_MINER_DEFAULT_FLAGS;

  btc_buffer_init(&miner->cbflags);
  btc_vector_init(&miner->addrs);
  btc_cpuminer_init(&miner->cpu, miner, btc_sys_numcpu());

  btc_buffer_set(&miner->cbflags, default_flags, sizeof(default_flags) - 1);

  return miner;
}

void
btc_miner_destroy(btc_miner_t *miner) {
  size_t i;

  for (i = 0; i < miner->addrs.length; i++)
    btc_address_destroy(miner->addrs.items[i]);

  btc_vector_clear(&miner->addrs);
  btc_buffer_clear(&miner->cbflags);
  btc_cpuminer_clear(&miner->cpu);

  btc_free(miner);
}

void
btc_miner_set_logger(btc_miner_t *miner, btc_logger_t *logger) {
  miner->logger = logger;
}

void
btc_miner_set_timedata(btc_miner_t *miner, const btc_timedata_t *td) {
  miner->timedata = td;
}

int
btc_miner_open(btc_miner_t *miner, unsigned int flags) {
  btc_log_info(miner, "Opening miner.");

  miner->flags = flags;

  return 1;
}

void
btc_miner_close(btc_miner_t *miner) {
  btc_log_info(miner, "Closing miner.");

  if (miner->cpu.mining)
    btc_cpuminer_stop(&miner->cpu);
}

void
btc_miner_add_address(btc_miner_t *miner, const btc_address_t *addr) {
  btc_vector_push(&miner->addrs, btc_address_clone(addr));
}

void
btc_miner_get_address(btc_miner_t *miner, btc_address_t *addr) {
  if (miner->addrs.length == 0) {
    btc_address_init(addr);
  } else {
    size_t i = btc_uniform(miner->addrs.length);

    btc_address_copy(addr, miner->addrs.items[i]);
  }
}

void
btc_miner_set_data(btc_miner_t *miner,
                   const uint8_t *flags,
                   size_t length) {
  CHECK(length <= 70);

  btc_buffer_set(&miner->cbflags, flags, length);
}

void
btc_miner_set_flags(btc_miner_t *miner, const char *flags) {
  btc_miner_set_data(miner, (const uint8_t *)flags, strlen(flags));
}

void
btc_miner_update_time(btc_miner_t *miner, btc_tmpl_t *bt) {
  int64_t now = btc_timedata_now(miner->timedata);

  if (now < bt->mtp + 1)
    now = bt->mtp + 1;

  bt->time = now;
}

static int
cmp_rate(const void *ap, const void *bp) {
  const btc_blockentry_t *a = ap;
  const btc_blockentry_t *b = bp;

  int64_t x = a->rate;
  int64_t y = b->rate;

  if (a->desc_rate > a->rate)
    x = a->desc_rate;

  if (b->desc_rate > b->rate)
    y = b->desc_rate;

  return BTC_CMP(y, x);
}

static void
btc_miner_assemble(btc_miner_t *miner, btc_tmpl_t *bt) {
  const btc_hashmap_t *map = btc_mempool_map(miner->mempool);
  int64_t locktime = btc_tmpl_locktime(bt);
  btc_hashmap_t depmap;
  btc_vector_t queue;
  btc_mapiter_t it;
  size_t i;

  btc_hashmap_init(&depmap);
  btc_vector_init(&queue);

  btc_map_each(map, it) {
    const btc_mpentry_t *entry = map->vals[it];
    btc_blockentry_t *item = btc_blockentry_create();

    btc_blockentry_set_mpentry(item, entry);

    for (i = 0; i < item->tx->inputs.length; i++) {
      const btc_input_t *input = item->tx->inputs.items[i];
      const uint8_t *hash = input->prevout.hash;

      if (!btc_mempool_has(miner->mempool, hash))
        continue;

      item->dep_count += 1;

      if (!btc_hashmap_has(&depmap, hash))
        btc_hashmap_put(&depmap, hash, btc_vector_create());

      btc_vector_push(btc_hashmap_get(&depmap, hash), item);
    }

    if (item->dep_count > 0)
      continue;

    btc_heap_insert(&queue, item, cmp_rate);
  }

  while (queue.length > 0) {
    const btc_blockentry_t *item = btc_heap_shift(&queue, cmp_rate);
    btc_vector_t *deps;

    if (!btc_tx_is_final(item->tx, bt->height, locktime))
      continue;

    if (!(bt->flags & BTC_SCRIPT_VERIFY_WITNESS)) {
      if (btc_tx_has_witness(item->tx))
        continue;
    }

    if (bt->weight + item->weight > BTC_MAX_POLICY_BLOCK_WEIGHT)
      continue;

    if (bt->sigops + item->sigops > BTC_MAX_BLOCK_SIGOPS_COST)
      continue;

    bt->weight += item->weight;
    bt->sigops += item->sigops;
    bt->fees += item->fee;

    btc_vector_push(&bt->txs, item);

    deps = btc_hashmap_get(&depmap, item->hash);

    if (deps == NULL)
      continue;

    for (i = 0; i < deps->length; i++) {
      btc_blockentry_t *child = deps->items[i];

      if (--child->dep_count == 0)
        btc_heap_insert(&queue, child, cmp_rate);
    }
  }

  btc_tmpl_refresh(bt);

  btc_map_each(&depmap, it)
    btc_vector_destroy(depmap.vals[it]);

  btc_hashmap_clear(&depmap);
  btc_vector_clear(&queue);
}

btc_tmpl_t *
btc_miner_template(btc_miner_t *miner) {
  const btc_entry_t *tip = btc_chain_tip(miner->chain);
  uint32_t version = btc_chain_compute_version(miner->chain, tip);
  int64_t mtp = btc_entry_median_time(tip);
  int64_t time = btc_timedata_now(miner->timedata);
  btc_tmpl_t *bt = btc_tmpl_create();
  btc_deployment_state_t state;
  uint32_t bits;

  if (time < mtp + 1)
    time = mtp + 1;

  btc_chain_get_deployments(miner->chain, &state, time, tip);

  bits = btc_chain_get_target(miner->chain, time, tip);

  bt->version = version;
  btc_hash_copy(bt->prev_block, tip->hash);
  bt->time = time;
  bt->bits = bits;
  bt->height = tip->height + 1;
  bt->mtp = mtp;
  bt->flags = state.flags;
  bt->interval = miner->network->halving_interval;
  bt->weight = 4000; /* reserved */
  bt->sigops = 400; /* reserved */

  btc_buffer_copy(&bt->cbflags, &miner->cbflags);
  btc_miner_get_address(miner, &bt->address);

  if (miner->mempool != NULL)
    btc_miner_assemble(miner, bt);

  btc_log_debug(miner,
    "Created block tmpl (height=%d, weight=%zu, fees=%v, txs=%zu).",
    bt->height, bt->weight, bt->fees, bt->txs.length + 1);

  return bt;
}

int
btc_miner_getgenerate(btc_miner_t *miner) {
  return miner->cpu.mining;
}

void
btc_miner_setgenerate(btc_miner_t *miner, int value, int active) {
  btc_cpuminer_setgenerate(&miner->cpu, value, active);
}

void
btc_miner_generate(btc_miner_t *miner, int blocks, const btc_address_t *addr) {
  int i;

  for (i = 0; i < blocks; i++) {
    btc_tmpl_t *bt = btc_miner_template(miner);
    btc_block_t *block;

    if (addr != NULL)
      btc_address_copy(&bt->address, addr);

    block = btc_tmpl_mine(bt);

    CHECK(btc_chain_add(miner->chain, block, BTC_BLOCK_DEFAULT_FLAGS, 0));

    btc_block_destroy(block);
    btc_tmpl_destroy(bt);
  }
}
