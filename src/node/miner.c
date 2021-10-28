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

#include <satoshi/address.h>
#include <satoshi/block.h>
#include <satoshi/buffer.h>
#include <satoshi/coins.h>
#include <satoshi/consensus.h>
#include <satoshi/crypto/hash.h>
#include <satoshi/crypto/merkle.h>
#include <satoshi/crypto/rand.h>
#include <satoshi/entry.h>
#include <satoshi/header.h>
#include <satoshi/heap.h>
#include <satoshi/map.h>
#include <satoshi/net.h>
#include <satoshi/netaddr.h>
#include <satoshi/netmsg.h>
#include <satoshi/network.h>
#include <satoshi/policy.h>
#include <satoshi/script.h>
#include <satoshi/tx.h>
#include <satoshi/util.h>
#include <satoshi/vector.h>

#include "../bio.h"
#include "../impl.h"
#include "../internal.h"

/*
 * Constants
 */

static const uint8_t zero_nonce[32] = {0};
static const uint8_t default_flags[] = "mined by libsatoshi";

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
  z->rate = btc_get_rate(size, z->fee);
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
  z->rate = btc_get_rate(x->size, x->delta_fee);
  z->weight = btc_tx_weight(x->tx);
  z->sigops = x->sigops;
  z->desc_rate = btc_get_rate(x->desc_size, x->desc_fee);
  z->dep_count = 0;
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
btc_tmpl_witness_hash(uint8_t *hash, const btc_tmpl_t *bt) {
  size_t length = bt->txs.length + 1;
  uint8_t *hashes = (uint8_t *)btc_malloc(length * 32);
  const btc_blockentry_t *entry;
  btc_hash256_t ctx;
  uint8_t root[32];
  size_t i;

  btc_hash_init(&hashes[0 * 32]);

  for (i = 1; i < length; i++) {
    entry = (const btc_blockentry_t *)bt->txs.items[i - 1];

    btc_hash_copy(&hashes[i * 32], entry->whash);
  }

  CHECK(btc_merkle_root(root, hashes, length));

  btc_free(hashes);

  btc_hash256_init(&ctx);
  btc_hash256_update(&ctx, root, 32);
  btc_hash256_update(&ctx, zero_nonce, 32);
  btc_hash256_final(&ctx, hash);
}

void
btc_tmpl_refresh(btc_tmpl_t *bt) {
  btc_tmpl_witness_hash(bt->commitment, bt);
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
  btc_uint32_write(nonce_raw, btc_random());
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
  size_t length = bt->txs.length + 1;
  uint8_t *hashes = (uint8_t *)btc_malloc(length * 32);
  const btc_blockentry_t *entry;
  size_t i;

  btc_hash_copy(&hashes[0 * 32], hash);

  for (i = 1; i < length; i++) {
    entry = (const btc_blockentry_t *)bt->txs.items[i - 1];

    btc_hash_copy(&hashes[i * 32], entry->hash);
  }

  CHECK(btc_merkle_root(root, hashes, length));

  btc_free(hashes);
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
 * Miner
 */

struct btc_miner_s {
  const btc_network_t *network;
  btc_loop_t *loop;
  btc_logger_t *logger;
  const btc_timedata_t *timedata;
  btc_chain_t *chain;
  btc_mempool_t *mempool;
  btc_buffer_t cbflags;
  btc_vector_t addrs;
};

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

  btc_buffer_init(&miner->cbflags);
  btc_vector_init(&miner->addrs);

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

static void
btc_miner_log(btc_miner_t *miner, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  btc_logger_write(miner->logger, "miner", fmt, ap);
  va_end(ap);
}

int
btc_miner_open(btc_miner_t *miner) {
  btc_miner_log(miner, "Opening miner.");
  return 1;
}

void
btc_miner_close(btc_miner_t *miner) {
  (void)miner;
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
  btc_miner_set_data(miner, (uint8_t *)flags, strlen(flags));
}

void
btc_miner_update_time(btc_miner_t *miner, btc_tmpl_t *bt) {
  int64_t now = btc_timedata_now(miner->timedata);

  if (now < bt->mtp + 1)
    now = bt->mtp + 1;

  bt->time = now;
}

static int64_t
cmp_rate(void *ap, void *bp) {
  btc_blockentry_t *a = ap;
  btc_blockentry_t *b = bp;
  int64_t x = a->rate;
  int64_t y = b->rate;

  if (a->desc_rate > a->rate)
    x = a->desc_rate;

  if (b->desc_rate > b->rate)
    y = b->desc_rate;

  return y - x;
}

static void
btc_miner_assemble(btc_miner_t *miner, btc_tmpl_t *bt) {
  btc_hashmap_t *depmap = btc_hashmap_create();
  int64_t locktime = btc_tmpl_locktime(bt);
  const btc_mpentry_t *entry;
  btc_vector_t queue;
  btc_mpiter_t iter;
  size_t i;

  btc_vector_init(&queue);

  btc_mempool_iterate(&iter, miner->mempool);

  while (btc_mempool_next(&entry, &iter)) {
    btc_blockentry_t *item = btc_blockentry_create();

    btc_blockentry_set_mpentry(item, entry);

    for (i = 0; i < item->tx->inputs.length; i++) {
      const btc_input_t *input = item->tx->inputs.items[i];
      const uint8_t *hash = input->prevout.hash;

      if (!btc_mempool_has(miner->mempool, hash))
        continue;

      item->dep_count += 1;

      if (!btc_hashmap_has(depmap, hash))
        btc_hashmap_put(depmap, hash, btc_vector_create());

      btc_vector_push(btc_hashmap_get(depmap, hash), item);
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

    deps = btc_hashmap_get(depmap, item->hash);

    if (deps == NULL)
      continue;

    for (i = 0; i < deps->length; i++) {
      btc_blockentry_t *child = deps->items[i];

      if (--child->dep_count == 0)
        btc_heap_insert(&queue, child, cmp_rate);
    }
  }

  btc_tmpl_refresh(bt);

  btc_hashmap_iterate(&iter, depmap);

  while (btc_hashmap_next(&iter))
    btc_vector_destroy(iter.val);

  btc_hashmap_destroy(depmap);
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

  btc_miner_log(miner,
    "Created block tmpl (height=%d, weight=%zu, fees=%v, txs=%zu).",
    bt->height,
    bt->weight,
    bt->fees,
    bt->txs.length + 1);

  return bt;
}
