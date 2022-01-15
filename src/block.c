/*!
 * block.c - block for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <mako/block.h>
#include <mako/consensus.h>
#include <mako/crypto/hash.h>
#include <mako/crypto/merkle.h>
#include <mako/header.h>
#include <mako/netmsg.h>
#include <mako/script.h>
#include <mako/tx.h>
#include <mako/util.h>
#include "impl.h"
#include "internal.h"

/*
 * Block
 */

DEFINE_SERIALIZABLE_REFOBJ(btc_block, SCOPE_EXTERN)

void
btc_block_init(btc_block_t *z) {
  btc_header_init(&z->header);
  btc_txvec_init(&z->txs);
  z->_refs = 0;
}

void
btc_block_clear(btc_block_t *z) {
  btc_header_clear(&z->header);
  btc_txvec_clear(&z->txs);
}

void
btc_block_copy(btc_block_t *z, const btc_block_t *x) {
  btc_header_copy(&z->header, &x->header);
  btc_txvec_copy(&z->txs, &x->txs);
}

int
btc_block_has_witness(const btc_block_t *blk) {
  size_t i;

  for (i = 0; i < blk->txs.length; i++) {
    if (btc_tx_has_witness(blk->txs.items[i]))
      return 1;
  }

  return 0;
}

int
btc_block_merkle_root(uint8_t *root, const btc_block_t *blk) {
  size_t length = blk->txs.length;
  uint8_t *hashes = btc_malloc((length + 1) * 32);
  size_t i;
  int ret;

  for (i = 0; i < length; i++)
    btc_hash_copy(&hashes[i * 32], blk->txs.items[i]->hash);

  ret = btc_merkle_root(root, hashes, length);

  btc_free(hashes);

  return ret;
}

int
btc_block_witness_root(uint8_t *root, const btc_block_t *blk) {
  size_t length = blk->txs.length;
  uint8_t *hashes = btc_malloc((length + 1) * 32);
  size_t i;
  int ret;

  btc_hash_init(&hashes[0 * 32]);

  for (i = 1; i < length; i++)
    btc_hash_copy(&hashes[i * 32], blk->txs.items[i]->whash);

  ret = btc_merkle_root(root, hashes, length);

  btc_free(hashes);

  return ret;
}

const uint8_t *
btc_block_witness_nonce(const btc_block_t *blk) {
  const btc_input_t *input;
  const btc_tx_t *tx;

  if (blk->txs.length == 0)
    return NULL;

  tx = blk->txs.items[0];

  if (tx->inputs.length != 1)
    return NULL;

  input = tx->inputs.items[0];

  if (input->witness.length != 1)
    return NULL;

  if (input->witness.items[0]->length != 32)
    return NULL;

  return input->witness.items[0]->data;
}

int
btc_block_create_commitment_hash(uint8_t *hash, const btc_block_t *blk) {
  const uint8_t *nonce = btc_block_witness_nonce(blk);
  uint8_t root[32];

  if (nonce == NULL)
    return 0;

  if (!btc_block_witness_root(root, blk))
    return 0;

  btc_hash256_root(hash, root, nonce);

  return 1;
}

const uint8_t *
btc_block_get_commitment_hash(const btc_block_t *blk) {
  const btc_output_t *output;
  const btc_tx_t *tx;
  const uint8_t *hash;
  size_t i;

  if (blk->txs.length == 0)
    return NULL;

  tx = blk->txs.items[0];

  for (i = tx->outputs.length - 1; i != (size_t)-1; i--) {
    output = tx->outputs.items[i];

    if (btc_script_get_commitment(&hash, &output->script))
      return hash;
  }

  return NULL;
}

static int
btc_block_throw(btc_verify_error_t *err,
                const char *reason,
                int score,
                int malleated) {
  if (err != NULL) {
    btc_hash_init(err->hash);

    err->code = BTC_REJECT_INVALID;
    err->reason = reason;
    err->score = score;
    err->malleated = malleated;
  }

  return 0;
}

#define THROW(reason, score, malleated) do {             \
  return btc_block_throw(err, reason, score, malleated); \
} while (0)

int
btc_block_check_sanity(btc_verify_error_t *err,
                       const btc_block_t *blk,
                       int64_t now) {
  uint8_t root[32];
  int sigops = 0;
  size_t i;

  /* Check timestamp. */
  if (blk->header.time > now + 2 * 60 * 60)
    THROW("time-too-new", 0, 1);

  /* Compute merkle root. */
  if (!btc_block_merkle_root(root, blk))
    THROW("bad-txns-duplicate", 100, 1);

  /* Check merkle root. */
  if (!btc_hash_equal(blk->header.merkle_root, root))
    THROW("bad-txnmrklroot", 100, 1);

  /* Check base size. */
  if (blk->txs.length == 0
      || blk->txs.length > BTC_MAX_BLOCK_SIZE
      || btc_block_base_size(blk) > BTC_MAX_BLOCK_SIZE) {
    THROW("bad-blk-length", 100, 0);
  }

  /* First transaction must be a coinbase. */
  if (!btc_tx_is_coinbase(blk->txs.items[0]))
    THROW("bad-cb-missing", 100, 0);

  /* Test all transactions. */
  for (i = 0; i < blk->txs.length; i++) {
    const btc_tx_t *tx = blk->txs.items[i];

    /* Remaining transactions must not be coinbases. */
    if (i > 0 && btc_tx_is_coinbase(tx))
      THROW("bad-cb-multiple", 100, 0);

    /* Transaction sanity checks. */
    if (!btc_tx_check_sanity(err, tx))
      return 0;

    /* Count legacy sigops (do not count scripthash or witness). */
    sigops += btc_tx_legacy_sigops(tx);
  }

  /* Check legacy sigops. */
  if (sigops * BTC_WITNESS_SCALE_FACTOR > BTC_MAX_BLOCK_SIGOPS_COST)
    THROW("bad-blk-sigops", 100, 0);

  return 1;
}

#undef THROW

int32_t
btc_block_coinbase_height(const btc_block_t *blk) {
  const btc_tx_t *tx;

  if (blk->header.version < 2)
    return -1;

  if (blk->txs.length == 0)
    return -1;

  tx = blk->txs.items[0];

  if (tx->inputs.length == 0)
    return -1;

  return btc_script_get_height(&tx->inputs.items[0]->script);
}

int64_t
btc_block_claimed(const btc_block_t *blk) {
  CHECK(blk->txs.length > 0);
  return btc_tx_output_value(blk->txs.items[0]);
}

size_t
btc_block_base_size(const btc_block_t *blk) {
  return btc_header_size(&blk->header) + btc_txvec_base_size(&blk->txs);
}

size_t
btc_block_witness_size(const btc_block_t *blk) {
  return btc_txvec_witness_size(&blk->txs);
}

size_t
btc_block_size(const btc_block_t *blk) {
  return btc_block_base_size(blk) + btc_block_witness_size(blk);
}

size_t
btc_block_weight(const btc_block_t *blk) {
  size_t base = btc_block_base_size(blk);
  size_t wit = btc_block_witness_size(blk);
  return (base * BTC_WITNESS_SCALE_FACTOR) + wit;
}

size_t
btc_block_virtual_size(const btc_block_t *blk) {
  size_t weight = btc_block_weight(blk);
  return (weight + BTC_WITNESS_SCALE_FACTOR - 1) / BTC_WITNESS_SCALE_FACTOR;
}

uint8_t *
btc_block_base_write(uint8_t *zp, const btc_block_t *x) {
  zp = btc_header_write(zp, &x->header);
  zp = btc_txvec_base_write(zp, &x->txs);
  return zp;
}

uint8_t *
btc_block_write(uint8_t *zp, const btc_block_t *x) {
  zp = btc_header_write(zp, &x->header);
  zp = btc_txvec_write(zp, &x->txs);
  return zp;
}

int
btc_block_read(btc_block_t *z, const uint8_t **xp, size_t *xn) {
  if (!btc_header_read(&z->header, xp, xn))
    return 0;

  if (!btc_txvec_read(&z->txs, xp, xn))
    return 0;

  return 1;
}
