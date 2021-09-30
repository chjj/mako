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
  z->tx = btc_tx_clone(&x->tx);
  z->hash = z->tx->hash;
  z->whash = z->tx->whash;
  z->fee = x->fee;
  z->rate = btc_get_rate(x->size, x->delta_fee);
  z->weight = btc_tx_weight(&x->tx);
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
  static unsigned char cbflags[] = "mined by libsatoshi";

  memset(bt, 0, sizeof(*bt));

  bt->version = 4;
  bt->time = btc_now();
  bt->bits = 0x207fffff;
  bt->mtp = bt->time - 10 * 60;
  bt->flags = BTC_SCRIPT_STANDARD_VERIFY_FLAGS;
  bt->interval = 210000;
  bt->weight = 4000;
  bt->sigops = 400;

  btc_buffer_init(&bt->cbflags);
  btc_buffer_set(&bt->cbflags, cbflags, sizeof(cbflags) - 1);

  btc_address_init(&bt->address);

  btc_vector_init(&bt->txs);
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
  size_t len;

  btc_writer_init(&writer);

  /* Coinbase input. */
  input = btc_input_create();

  /* Height (required in v2+ blocks) */
  if (bt->height == 0) {
    btc_writer_push_op(&writer, 0);
  } else if (bt->height >= 1 && bt->height <= 16) {
    btc_writer_push_op(&writer, 0x50 + bt->height);
  } else {
    len = btc_scriptnum_export(height_raw, bt->height);

    btc_writer_push_data(&writer, height_raw, len);
  }

  /* Coinbase flags. */
  CHECK(bt->cbflags.length <= 70);
  btc_writer_push_data(&writer, bt->cbflags.data,
                                bt->cbflags.length);

  /* Smaller nonce for good measure. */
  btc_uint32_write(nonce_raw, btc_random());
  btc_writer_push_data(&writer, nonce_raw, 4);

  /* Extra nonce: incremented when the nonce overflows. */
  write32be(extra_raw + 0, nonce1);
  write32be(extra_raw + 4, nonce2);
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
  const btc_tx_t *tx;
  size_t i;

  hdr->version = bt->version;
  btc_hash_copy(hdr->prev_block, bt->prev_block);
  btc_hash_copy(hdr->merkle_root, proof->root);
  hdr->time = proof->time;
  hdr->bits = bt->bits;
  hdr->nonce = proof->nonce;

  btc_txvec_push(&block->txs, cb);

  for (i = 0; i < bt->txs.length; i++) {
    tx = ((const btc_blockentry_t *)bt->txs.items[i])->tx;

    btc_txvec_push(&block->txs, btc_tx_clone(tx));
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
  const btc_tx_t *tx;
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
    tx = ((const btc_blockentry_t *)bt->txs.items[i])->tx;

    btc_txvec_push(&block->txs, btc_tx_clone(tx));
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

  if (bt->weight + item->weight > BTC_MAX_BLOCK_WEIGHT)
    goto fail;

  if (bt->sigops + item->sigops > BTC_MAX_BLOCK_SIGOPS_COST)
    goto fail;

  if (!(bt->flags & BTC_SCRIPT_VERIFY_WITNESS)) {
    if (btc_tx_has_witness(tx))
      goto fail;
  }

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
