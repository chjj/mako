/*!
 * tx.c - tx for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <mako/address.h>
#include <mako/bloom.h>
#include <mako/coins.h>
#include <mako/consensus.h>
#include <mako/crypto/ecc.h>
#include <mako/crypto/hash.h>
#include <mako/map.h>
#include <mako/netmsg.h>
#include <mako/policy.h>
#include <mako/script.h>
#include <mako/tx.h>
#include <mako/util.h>
#include <mako/vector.h>
#include "impl.h"
#include "internal.h"

/*
 * Transaction
 */

DEFINE_SERIALIZABLE_REFOBJ(btc_tx, SCOPE_EXTERN)

void
btc_tx_init(btc_tx_t *tx) {
  btc_hash_init(tx->hash);
  btc_hash_init(tx->whash);
  tx->version = 1;
  btc_inpvec_init(&tx->inputs);
  btc_outvec_init(&tx->outputs);
  tx->locktime = 0;
  tx->_index = 0;
  tx->_refs = 0;
}

void
btc_tx_clear(btc_tx_t *tx) {
  btc_inpvec_clear(&tx->inputs);
  btc_outvec_clear(&tx->outputs);
}

void
btc_tx_copy(btc_tx_t *z, const btc_tx_t *x) {
  btc_hash_copy(z->hash, x->hash);
  btc_hash_copy(z->whash, x->whash);
  z->version = x->version;
  btc_inpvec_copy(&z->inputs, &x->inputs);
  btc_outvec_copy(&z->outputs, &x->outputs);
  z->locktime = x->locktime;
}

int
btc_tx_is_coinbase(const btc_tx_t *tx) {
  if (tx->inputs.length != 1)
    return 0;

  return btc_outpoint_is_null(&tx->inputs.items[0]->prevout);
}

int
btc_tx_has_witness(const btc_tx_t *tx) {
  size_t i;

  for (i = 0; i < tx->inputs.length; i++) {
    if (tx->inputs.items[i]->witness.length > 0)
      return 1;
  }

  return 0;
}

void
btc_tx_txid(uint8_t *hash, const btc_tx_t *tx) {
  btc_hash256_t ctx;
  btc_hash256_init(&ctx);
  btc_uint32_update(&ctx, tx->version);
  btc_inpvec_update(&ctx, &tx->inputs);
  btc_outvec_update(&ctx, &tx->outputs);
  btc_uint32_update(&ctx, tx->locktime);
  btc_hash256_final(&ctx, hash);
}

void
btc_tx_wtxid(uint8_t *hash, const btc_tx_t *tx) {
  btc_hash256_t ctx;
  size_t i;

  if (!btc_tx_has_witness(tx)) {
    btc_tx_txid(hash, tx);
    return;
  }

  btc_hash256_init(&ctx);
  btc_uint32_update(&ctx, tx->version);
  btc_uint8_update(&ctx, 0);
  btc_uint8_update(&ctx, 1);
  btc_inpvec_update(&ctx, &tx->inputs);
  btc_outvec_update(&ctx, &tx->outputs);

  for (i = 0; i < tx->inputs.length; i++)
    btc_stack_update(&ctx, &tx->inputs.items[i]->witness);

  btc_uint32_update(&ctx, tx->locktime);
  btc_hash256_final(&ctx, hash);
}

void
btc_tx_refresh(btc_tx_t *tx) {
  if (btc_tx_has_witness(tx)) {
    btc_tx_txid(tx->hash, tx);
    btc_tx_wtxid(tx->whash, tx);
  } else {
    btc_tx_txid(tx->hash, tx);
    btc_hash_copy(tx->whash, tx->hash);
  }
}

static void
btc_tx_sighash_v0(uint8_t *hash,
                  const btc_tx_t *tx,
                  size_t index,
                  const btc_script_t *prev,
                  int type) {
  const btc_input_t *input;
  const btc_output_t *output;
  btc_hash256_t ctx;
  size_t i;

  if ((type & 0x1f) == BTC_SIGHASH_SINGLE) {
    /**
     * Satoshi's code returned 1 as an error code.
     * This ended up being cast to a uint256[1][2].
     *
     * [1] https://bitcointalk.org/index.php?topic=260595.0
     * [2] https://mempool.space/tx/315ac7d4c26d69668129cc352851d9389b4a6868f1509c6c8b66bead11e2619f
     */
    if (index >= tx->outputs.length) {
      btc_hash_init(hash);
      hash[0] = 0x01;
      return;
    }
  }

  /* Start hashing. */
  btc_hash256_init(&ctx);

  btc_uint32_update(&ctx, tx->version);

  /* Serialize inputs. */
  if (type & BTC_SIGHASH_ANYONECANPAY) {
    /* Serialize only the current
       input if ANYONECANPAY. */
    input = tx->inputs.items[index];

    /* Count. */
    btc_size_update(&ctx, 1);

    /* Outpoint. */
    btc_outpoint_update(&ctx, &input->prevout);

    /* Replace script with previous
       output script if current index. */
    btc_script_update_v0(&ctx, prev);
    btc_uint32_update(&ctx, input->sequence);
  } else {
    btc_size_update(&ctx, tx->inputs.length);

    for (i = 0; i < tx->inputs.length; i++) {
      input = tx->inputs.items[i];

      /* Outpoint. */
      btc_outpoint_update(&ctx, &input->prevout);

      /* Replace script with previous
         output script if current index. */
      if (i == index) {
        btc_script_update_v0(&ctx, prev);
        btc_uint32_update(&ctx, input->sequence);
        continue;
      }

      /* Script is null. */
      btc_size_update(&ctx, 0);

      /* Sequences are 0 if NONE or SINGLE. */
      switch (type & 0x1f) {
        case BTC_SIGHASH_NONE:
        case BTC_SIGHASH_SINGLE:
          btc_uint32_update(&ctx, 0);
          break;
        default:
          btc_uint32_update(&ctx, input->sequence);
          break;
      }
    }
  }

  /* Serialize outputs. */
  switch (type & 0x1f) {
    case BTC_SIGHASH_NONE: {
      /* No outputs if NONE. */
      btc_size_update(&ctx, 0);
      break;
    }
    case BTC_SIGHASH_SINGLE: {
      output = tx->outputs.items[index];

      /* Drop all outputs after the
         current input index if SINGLE. */
      btc_size_update(&ctx, index + 1);

      for (i = 0; i < index; i++) {
        /* Null all outputs not at
           current input index. */
        btc_int64_update(&ctx, -1);
        btc_size_update(&ctx, 0);
      }

      /* Regular serialization
         at current input index. */
      btc_output_update(&ctx, output);

      break;
    }
    default: {
      /* Regular output serialization if ALL. */
      btc_size_update(&ctx, tx->outputs.length);

      for (i = 0; i < tx->outputs.length; i++) {
        output = tx->outputs.items[i];
        btc_output_update(&ctx, output);
      }

      break;
    }
  }

  btc_uint32_update(&ctx, tx->locktime);

  /* Append the hash type. */
  btc_int32_update(&ctx, type);

  btc_hash256_final(&ctx, hash);
}

static void
btc_tx_sighash_v1(uint8_t *hash,
                  const btc_tx_t *tx,
                  size_t index,
                  const btc_script_t *prev,
                  int64_t value,
                  int type,
                  btc_tx_cache_t *cache) {
  const btc_input_t *input = tx->inputs.items[index];
  uint8_t prevouts[32];
  uint8_t sequences[32];
  uint8_t outputs[32];
  btc_hash256_t ctx;
  size_t i;

  btc_hash_init(prevouts);
  btc_hash_init(sequences);
  btc_hash_init(outputs);

  if (!(type & BTC_SIGHASH_ANYONECANPAY)) {
    if (cache != NULL && cache->has_prevouts) {
      btc_hash_copy(prevouts, cache->prevouts);
    } else {
      btc_hash256_init(&ctx);

      for (i = 0; i < tx->inputs.length; i++)
        btc_outpoint_update(&ctx, &tx->inputs.items[i]->prevout);

      btc_hash256_final(&ctx, prevouts);

      if (cache != NULL) {
        btc_hash_copy(cache->prevouts, prevouts);
        cache->has_prevouts = 1;
      }
    }
  }

  if (!(type & BTC_SIGHASH_ANYONECANPAY)
      && (type & 0x1f) != BTC_SIGHASH_SINGLE
      && (type & 0x1f) != BTC_SIGHASH_NONE) {
    if (cache != NULL && cache->has_sequences) {
      btc_hash_copy(sequences, cache->sequences);
    } else {
      btc_hash256_init(&ctx);

      for (i = 0; i < tx->inputs.length; i++)
        btc_uint32_update(&ctx, tx->inputs.items[i]->sequence);

      btc_hash256_final(&ctx, sequences);

      if (cache != NULL) {
        btc_hash_copy(cache->sequences, sequences);
        cache->has_sequences = 1;
      }
    }
  }

  if ((type & 0x1f) != BTC_SIGHASH_SINGLE
      && (type & 0x1f) != BTC_SIGHASH_NONE) {
    if (cache != NULL && cache->has_outputs) {
      btc_hash_copy(outputs, cache->outputs);
    } else {
      btc_hash256_init(&ctx);

      for (i = 0; i < tx->outputs.length; i++)
        btc_output_update(&ctx, tx->outputs.items[i]);

      btc_hash256_final(&ctx, outputs);

      if (cache != NULL) {
        btc_hash_copy(cache->outputs, outputs);
        cache->has_outputs = 1;
      }
    }
  } else if ((type & 0x1f) == BTC_SIGHASH_SINGLE) {
    if (index < tx->outputs.length) {
      btc_hash256_init(&ctx);
      btc_output_update(&ctx, tx->outputs.items[index]);
      btc_hash256_final(&ctx, outputs);
    }
  }

  btc_hash256_init(&ctx);

  btc_uint32_update(&ctx, tx->version);
  btc_raw_update(&ctx, prevouts, 32);
  btc_raw_update(&ctx, sequences, 32);
  btc_outpoint_update(&ctx, &input->prevout);
  btc_script_update(&ctx, prev);
  btc_int64_update(&ctx, value);
  btc_uint32_update(&ctx, input->sequence);
  btc_raw_update(&ctx, outputs, 32);
  btc_uint32_update(&ctx, tx->locktime);
  btc_int32_update(&ctx, type);

  btc_hash256_final(&ctx, hash);
}

void
btc_tx_sighash(uint8_t *hash,
               const btc_tx_t *tx,
               size_t index,
               const btc_script_t *prev,
               int64_t value,
               int type,
               int version,
               btc_tx_cache_t *cache) {
  /* Traditional sighashing. */
  if (version == 0) {
    btc_tx_sighash_v0(hash, tx, index, prev, type);
    return;
  }

  /* Segwit sighashing. */
  if (version == 1) {
    btc_tx_sighash_v1(hash, tx, index, prev, value, type, cache);
    return;
  }

  btc_abort(); /* LCOV_EXCL_LINE */
}

int
btc_tx_verify(const btc_tx_t *tx, const btc_view_t *view, unsigned int flags) {
  const btc_input_t *input;
  const btc_coin_t *coin;
  btc_tx_cache_t cache;
  size_t i;

  memset(&cache, 0, sizeof(cache));

  for (i = 0; i < tx->inputs.length; i++) {
    input = tx->inputs.items[i];
    coin = btc_view_get(view, &input->prevout);

    if (coin == NULL)
      return 0;

    if (!btc_tx_verify_input(tx, i, &coin->output, flags, &cache))
      return 0;
  }

  return 1;
}

int
btc_tx_verify_input(const btc_tx_t *tx,
                    size_t index,
                    const btc_output_t *coin,
                    unsigned int flags,
                    btc_tx_cache_t *cache) {
  const btc_input_t *input = tx->inputs.items[index];

  int ret = btc_script_verify(&input->script,
                              &input->witness,
                              &coin->script,
                              tx,
                              index,
                              coin->value,
                              flags,
                              cache);

  return ret == BTC_SCRIPT_ERR_OK;
}

int
btc_tx_is_rbf(const btc_tx_t *tx) {
  size_t i;

  for (i = 0; i < tx->inputs.length; i++) {
    if (tx->inputs.items[i]->sequence < 0xfffffffe)
      return 1;
  }

  return 0;
}

int
btc_tx_is_final(const btc_tx_t *tx, int32_t height, int64_t time) {
  static unsigned int threshold = BTC_LOCKTIME_THRESHOLD;
  size_t i;

  if (tx->locktime == 0)
    return 1;

  if ((int64_t)tx->locktime < (tx->locktime < threshold ? height : time))
    return 1;

  for (i = 0; i < tx->inputs.length; i++) {
    if (tx->inputs.items[i]->sequence != 0xffffffff)
      return 0;
  }

  return 1;
}

int
btc_tx_verify_locktime(const btc_tx_t *tx, size_t index, int64_t predicate) {
  static unsigned int threshold = BTC_LOCKTIME_THRESHOLD;
  const btc_input_t *input = tx->inputs.items[index];

  /* Locktimes must be of the same type (blocks or seconds). */
  if ((tx->locktime < threshold) != (predicate < (int64_t)threshold))
    return 0;

  if (predicate > (int64_t)tx->locktime)
    return 0;

  if (input->sequence == 0xffffffff)
    return 0;

  return 1;
}

int
btc_tx_verify_sequence(const btc_tx_t *tx, size_t index, int64_t predicate) {
  static const uint32_t disable_flag = BTC_SEQUENCE_DISABLE_FLAG;
  static const uint32_t type_flag = BTC_SEQUENCE_TYPE_FLAG;
  static const uint32_t mask = BTC_SEQUENCE_MASK;
  const btc_input_t *input = tx->inputs.items[index];
  int64_t sequence = (int64_t)input->sequence;

  /* For future softfork capability. */
  if (predicate & disable_flag)
    return 1;

  /* Version must be >=2. */
  if (tx->version < 2)
    return 0;

  /* Cannot use the disable flag without
     the predicate also having the disable
     flag (for future softfork capability). */
  if (sequence & disable_flag)
    return 0;

  /* Locktimes must be of the same type (blocks or seconds). */
  if ((sequence & type_flag) != (predicate & type_flag))
    return 0;

  if ((predicate & mask) > (sequence & mask))
    return 0;

  return 1;
}

int64_t
btc_tx_input_value(const btc_tx_t *tx, const btc_view_t *view) {
  const btc_input_t *input;
  const btc_coin_t *coin;
  int64_t total = 0;
  size_t i;

  for (i = 0; i < tx->inputs.length; i++) {
    input = tx->inputs.items[i];
    coin = btc_view_get(view, &input->prevout);

    if (coin == NULL)
      return -1;

    total += coin->output.value;
  }

  return total;
}

int64_t
btc_tx_output_value(const btc_tx_t *tx) {
  int64_t total = 0;
  size_t i;

  for (i = 0; i < tx->outputs.length; i++)
    total += tx->outputs.items[i]->value;

  return total;
}

int64_t
btc_tx_fee(const btc_tx_t *tx, const btc_view_t *view) {
  int64_t inpval = btc_tx_input_value(tx, view);

  if (inpval < 0)
    return -1;

  return inpval - btc_tx_output_value(tx);
}

int
btc_tx_legacy_sigops(const btc_tx_t *tx) {
  const btc_input_t *input;
  const btc_output_t *output;
  int total = 0;
  size_t i;

  for (i = 0; i < tx->inputs.length; i++) {
    input = tx->inputs.items[i];
    total += btc_script_sigops(&input->script, 0);
  }

  for (i = 0; i < tx->outputs.length; i++) {
    output = tx->outputs.items[i];
    total += btc_script_sigops(&output->script, 0);
  }

  return total;
}

int
btc_tx_p2sh_sigops(const btc_tx_t *tx, const btc_view_t *view) {
  const btc_input_t *input;
  const btc_coin_t *coin;
  int total = 0;
  size_t i;

  if (btc_tx_is_coinbase(tx))
    return 0;

  for (i = 0; i < tx->inputs.length; i++) {
    input = tx->inputs.items[i];
    coin = btc_view_get(view, &input->prevout);

    if (coin == NULL)
      continue;

    if (!btc_script_is_p2sh(&coin->output.script))
      continue;

    total += btc_script_p2sh_sigops(&coin->output.script, &input->script);
  }

  return total;
}

int
btc_tx_witness_sigops(const btc_tx_t *tx, const btc_view_t *view) {
  const btc_input_t *input;
  const btc_coin_t *coin;
  int total = 0;
  size_t i;

  if (btc_tx_is_coinbase(tx))
    return 0;

  for (i = 0; i < tx->inputs.length; i++) {
    input = tx->inputs.items[i];
    coin = btc_view_get(view, &input->prevout);

    if (coin == NULL)
      continue;

    total += btc_script_witness_sigops(&coin->output.script,
                                       &input->script,
                                       &input->witness);
  }

  return total;
}

int
btc_tx_sigops_cost(const btc_tx_t *tx,
                   const btc_view_t *view,
                   unsigned int flags) {
  int cost = btc_tx_legacy_sigops(tx) * BTC_WITNESS_SCALE_FACTOR;

  if (flags & BTC_SCRIPT_VERIFY_P2SH)
    cost += btc_tx_p2sh_sigops(tx, view) * BTC_WITNESS_SCALE_FACTOR;

  if (flags & BTC_SCRIPT_VERIFY_WITNESS)
    cost += btc_tx_witness_sigops(tx, view);

  return cost;
}

int
btc_tx_sigops(const btc_tx_t *tx, const btc_view_t *view, unsigned int flags) {
  int cost = btc_tx_sigops_cost(tx, view, flags);
  return (cost + BTC_WITNESS_SCALE_FACTOR - 1) / BTC_WITNESS_SCALE_FACTOR;
}

int
btc_tx_has_duplicate_inputs(const btc_tx_t *tx) {
  const btc_input_t *input;
  btc_outset_t set;
  size_t i;

  btc_outset_init(&set);

  for (i = 0; i < tx->inputs.length; i++) {
    input = tx->inputs.items[i];

    if (!btc_outset_put(&set, &input->prevout)) {
      btc_outset_clear(&set);
      return 1;
    }
  }

  btc_outset_clear(&set);

  return 0;
}

static int
btc_tx_throw(btc_verify_error_t *err,
             const char *reason,
             int score,
             int malleated,
             int result) {
  if (err != NULL) {
    btc_hash_init(err->hash);

    err->code = BTC_REJECT_INVALID;
    err->reason = reason;
    err->score = score;
    err->malleated = malleated;
  }

  return result;
}

#define THROW(reason, score, malleated, result) do {          \
  return btc_tx_throw(err, reason, score, malleated, result); \
} while (0)

int
btc_tx_check_sanity(btc_verify_error_t *err, const btc_tx_t *tx) {
  const btc_input_t *input;
  const btc_output_t *output;
  int64_t outval = 0;
  size_t i, size;

  if (tx->inputs.length == 0)
    THROW("bad-txns-vin-empty", 100, 0, 0);

  if (tx->outputs.length == 0)
    THROW("bad-txns-vout-empty", 100, 0, 0);

  if (btc_tx_base_size(tx) > BTC_MAX_BLOCK_SIZE)
    THROW("bad-txns-oversize", 100, 0, 0);

  for (i = 0; i < tx->outputs.length; i++) {
    output = tx->outputs.items[i];

    if (output->value < 0)
      THROW("bad-txns-vout-negative", 100, 0, 0);

    if (output->value > BTC_MAX_MONEY)
      THROW("bad-txns-vout-toolarge", 100, 0, 0);

    outval += output->value;

    if (outval < 0 || outval > BTC_MAX_MONEY)
      THROW("bad-txns-txouttotal-toolarge", 100, 0, 0);
  }

  if (btc_tx_has_duplicate_inputs(tx))
    THROW("bad-txns-inputs-duplicate", 100, 0, 0);

  if (btc_tx_is_coinbase(tx)) {
    size = tx->inputs.items[0]->script.length;

    if (size < 2 || size > 100)
      THROW("bad-cb-length", 100, 0, 0);
  } else {
    for (i = 0; i < tx->inputs.length; i++) {
      input = tx->inputs.items[i];

      if (btc_outpoint_is_null(&input->prevout))
        THROW("bad-txns-prevout-null", 10, 0, 0);
    }
  }

  return 1;
}

int64_t
btc_tx_check_inputs(btc_verify_error_t *err,
                    const btc_tx_t *tx,
                    const btc_view_t *view,
                    int32_t height) {
  const btc_input_t *input;
  const btc_coin_t *coin;
  int64_t outval, fee;
  int64_t inpval = 0;
  size_t i;

  for (i = 0; i < tx->inputs.length; i++) {
    input = tx->inputs.items[i];
    coin = btc_view_get(view, &input->prevout);

    if (coin == NULL)
      THROW("bad-txns-inputs-missingorspent", 0, 0, -1);

    if (coin->coinbase) {
      if (height - coin->height < BTC_COINBASE_MATURITY)
        THROW("bad-txns-premature-spend-of-coinbase", 0, 0, -1);
    }

    if (coin->output.value < 0 || coin->output.value > BTC_MAX_MONEY)
      THROW("bad-txns-inputvalues-outofrange", 100, 0, -1);

    inpval += coin->output.value;

    if (inpval < 0 || inpval > BTC_MAX_MONEY)
      THROW("bad-txns-inputvalues-outofrange", 100, 0, -1);
  }

  /* Overflows already checked in `btc_tx_check_sanity`. */
  outval = btc_tx_output_value(tx);

  if (inpval < outval)
    THROW("bad-txns-in-belowout", 100, 0, -1);

  fee = inpval - outval;

  if (fee < 0)
    THROW("bad-txns-fee-negative", 100, 0, -1);

  if (fee > BTC_MAX_MONEY)
    THROW("bad-txns-fee-outofrange", 100, 0, -1);

  return fee;
}

int
btc_tx_check_standard(btc_verify_error_t *err, const btc_tx_t *tx) {
  const btc_input_t *input;
  const btc_output_t *output;
  int nulldata = 0;
  size_t i;

  if (tx->version < 1 || tx->version > BTC_MAX_TX_VERSION)
    THROW("version", 0, 0, 0);

  if (btc_tx_weight(tx) > BTC_MAX_TX_WEIGHT) {
    if (btc_tx_base_size(tx) * BTC_WITNESS_SCALE_FACTOR > BTC_MAX_TX_WEIGHT)
      THROW("tx-size", 0, 0, 0);

    THROW("tx-size", 0, 1, 0);
  }

  for (i = 0; i < tx->inputs.length; i++) {
    input = tx->inputs.items[i];

    if (input->script.length > 1650)
      THROW("scriptsig-size", 0, 0, 0);

    if (!btc_script_is_push_only(&input->script))
      THROW("scriptsig-not-pushonly", 0, 0, 0);
  }

  for (i = 0; i < tx->outputs.length; i++) {
    output = tx->outputs.items[i];

    if (!btc_script_is_standard(&output->script))
      THROW("scriptpubkey", 0, 0, 0);

    if (btc_script_is_nulldata(&output->script)) {
      nulldata++;
      continue;
    }

#if !BTC_BARE_MULTISIG
    if (btc_script_is_multisig(&output->script))
      THROW("bare-multisig", 0, 0, 0);
#endif

    if (btc_output_is_dust(output, BTC_MIN_RELAY))
      THROW("dust", 0, 0, 0);
  }

  if (nulldata > 1)
    THROW("multi-op-return", 0, 0, 0);

  return 1;
}

#undef THROW

int
btc_tx_has_standard_inputs(const btc_tx_t *tx, const btc_view_t *view) {
  const btc_input_t *input;
  const btc_coin_t *coin;
  btc_script_t redeem;
  size_t i;

  if (btc_tx_is_coinbase(tx))
    return 1;

  for (i = 0; i < tx->inputs.length; i++) {
    input = tx->inputs.items[i];
    coin = btc_view_get(view, &input->prevout);

    if (coin == NULL)
      return 0;

    if (btc_script_is_p2pkh(&coin->output.script))
      continue;

    if (btc_script_is_p2sh(&coin->output.script)) {
      if (!btc_script_get_redeem(&redeem, &input->script))
        return 0;

      if (btc_script_sigops(&redeem, 1) > BTC_MAX_P2SH_SIGOPS)
        return 0;

      continue;
    }

    if (btc_script_is_unknown(&coin->output.script))
      return 0;
  }

  return 1;
}

int
btc_tx_has_standard_witness(const btc_tx_t *tx, const btc_view_t *view) {
  const btc_input_t *input;
  const btc_stack_t *witness;
  const btc_coin_t *coin;
  btc_script_t prev;
  size_t i, j;

  if (btc_tx_is_coinbase(tx))
    return 1;

  for (i = 0; i < tx->inputs.length; i++) {
    input = tx->inputs.items[i];
    witness = &input->witness;

    if (witness->length == 0)
      continue;

    coin = btc_view_get(view, &input->prevout);

    if (coin == NULL)
      return 0;

    btc_script_rocopy(&prev, &coin->output.script);

    if (btc_script_is_p2sh(&prev)) {
      if (!btc_script_get_redeem(&prev, &input->script))
        return 0;
    }

    if (!btc_script_is_program(&prev))
      return 0;

    if (btc_script_is_p2wsh(&prev)) {
      if (btc_stack_top(witness)->length > BTC_MAX_P2WSH_SIZE)
        return 0;

      if (witness->length - 1 > BTC_MAX_P2WSH_STACK)
        return 0;

      for (j = 0; j < witness->length - 1; j++) {
        if (witness->items[j]->length > BTC_MAX_P2WSH_PUSH)
          return 0;
      }

      continue;
    }
  }

  return 1;
}

static int
btc_script_matches(const btc_script_t *script, const btc_bloom_t *filter) {
  btc_reader_t reader;
  btc_opcode_t op;

  btc_reader_init(&reader, script);

  while (btc_reader_next(&op, &reader)) {
    if (op.length == 0)
      continue;

    if (btc_bloom_has(filter, op.data, op.length))
      return 1;
  }

  return 0;
}

int
btc_tx_matches(const btc_tx_t *tx, btc_bloom_t *filter) {
  /**
   * Test a transaction against a bloom filter using
   * the BIP37 matching algorithm. Note that this may
   * update the filter depending on what the `update`
   * value is.
   *
   * See: https://github.com/bitcoin/bips/blob/master/bip-0037.mediawiki
   */
  const btc_output_t *output;
  const btc_input_t *input;
  uint8_t raw[36];
  int found = 0;
  size_t i;

  /* 1. Test the tx hash. */
  if (btc_bloom_has(filter, tx->hash, 32))
    found = 1;

  /* 2. Test data elements in output scripts
        (may need to update filter on match). */
  btc_raw_write(raw, tx->hash, 32);

  for (i = 0; i < tx->outputs.length; i++) {
    output = tx->outputs.items[i];

    /* Test the output script. */
    if (btc_script_matches(&output->script, filter)) {
      if (filter->update == BTC_BLOOM_ALL) {
        btc_uint32_write(raw + 32, i);
        btc_bloom_add(filter, raw, 36);
      } else if (filter->update == BTC_BLOOM_PUBKEY_ONLY) {
        if (btc_script_is_p2pk(&output->script)
            || btc_script_is_multisig(&output->script)) {
          btc_uint32_write(raw + 32, i);
          btc_bloom_add(filter, raw, 36);
        }
      }
      found = 1;
    }
  }

  if (found)
    return found;

  /* 3. Test prev_out structure. */
  /* 4. Test data elements in input scripts. */
  for (i = 0; i < tx->inputs.length; i++) {
    input = tx->inputs.items[i];

    /* Test the COutPoint structure. */
    btc_outpoint_write(raw, &input->prevout);

    if (btc_bloom_has(filter, raw, 36))
      return 1;

    /* Test the input script. */
    if (btc_script_matches(&input->script, filter))
      return 1;
  }

  /* 5. No match. */
  return 0;
}

btc_vector_t *
btc_tx_input_addrs(const btc_tx_t *tx, const btc_view_t *view) {
  btc_vector_t *out = btc_vector_create();
  const btc_input_t *input;
  const btc_coin_t *coin;
  btc_address_t *addr;
  btc_address_t key;
  btc_addrset_t set;
  size_t i;

  btc_vector_grow(out, tx->inputs.length);
  btc_addrset_init(&set);

  for (i = 0; i < tx->inputs.length; i++) {
    input = tx->inputs.items[i];
    coin = btc_view_get(view, &input->prevout);

    if (coin == NULL)
      continue;

    if (!btc_address_set_script(&key, &coin->output.script))
      continue;

    if (btc_addrset_has(&set, &key))
      continue;

    addr = btc_address_clone(&key);

    btc_addrset_put(&set, addr);
    btc_vector_push(out, addr);
  }

  btc_addrset_clear(&set);

  return out;
}

btc_vector_t *
btc_tx_output_addrs(const btc_tx_t *tx) {
  btc_vector_t *out = btc_vector_create();
  const btc_output_t *output;
  btc_address_t *addr;
  btc_address_t key;
  btc_addrset_t set;
  size_t i;

  btc_vector_grow(out, tx->outputs.length);
  btc_addrset_init(&set);

  for (i = 0; i < tx->outputs.length; i++) {
    output = tx->outputs.items[i];

    if (!btc_address_set_script(&key, &output->script))
      continue;

    if (btc_addrset_has(&set, &key))
      continue;

    addr = btc_address_clone(&key);

    btc_addrset_put(&set, addr);
    btc_vector_push(out, addr);
  }

  btc_addrset_clear(&set);

  return out;
}

void
btc_tx_outpoint(btc_outpoint_t *out, const btc_tx_t *tx, uint32_t index) {
  btc_outpoint_set(out, tx->hash, index);
}

btc_coin_t *
btc_tx_coin(const btc_tx_t *tx, size_t index, int32_t height) {
  btc_coin_t *coin = btc_coin_create();

  coin->version = tx->version;
  coin->height = height;
  coin->coinbase = btc_tx_is_coinbase(tx);

  btc_output_copy(&coin->output, tx->outputs.items[index]);

  return coin;
}

void
btc_tx_add_input(btc_tx_t *tx, const uint8_t *hash, uint32_t index) {
  btc_input_t *input = btc_input_create();

  btc_outpoint_set(&input->prevout, hash, index);

  btc_inpvec_push(&tx->inputs, input);
}

void
btc_tx_add_outpoint(btc_tx_t *tx, const btc_outpoint_t *prevout) {
  btc_input_t *input = btc_input_create();

  btc_outpoint_copy(&input->prevout, prevout);

  btc_inpvec_push(&tx->inputs, input);
}

void
btc_tx_add_output(btc_tx_t *tx, const btc_address_t *addr, int64_t value) {
  btc_output_t *output = btc_output_create();

  btc_address_get_script(&output->script, addr);

  output->value = value;

  btc_outvec_push(&tx->outputs, output);
}

void
btc_tx_add_nulldata(btc_tx_t *tx, const uint8_t *data, size_t length) {
  btc_output_t *output = btc_output_create();

  btc_script_set_nulldata(&output->script, data, length);

  btc_outvec_push(&tx->outputs, output);
}

void
btc_tx_set_locktime(btc_tx_t *tx, uint32_t locktime) {
  size_t i;

  for (i = 0; i < tx->inputs.length; i++) {
    btc_input_t *input = tx->inputs.items[i];

    if (input->sequence == 0xffffffff)
      input->sequence = 0xfffffffe;
  }

  tx->locktime = locktime;
}

void
btc_tx_set_sequence(btc_tx_t *tx, size_t index, uint32_t locktime, int sec) {
  btc_input_t *input = tx->inputs.items[index];

  tx->version = 2;

  if (sec) {
    locktime >>= BTC_SEQUENCE_GRANULARITY;
    locktime &= BTC_SEQUENCE_MASK;
    locktime |= BTC_SEQUENCE_TYPE_FLAG;
  } else {
    locktime &= BTC_SEQUENCE_MASK;
  }

  input->sequence = locktime;
}

static int
input_compare(const void *xp, const void *yp) {
  const btc_input_t *x = *((const btc_input_t **)xp);
  const btc_input_t *y = *((const btc_input_t **)yp);

  return btc_outpoint_compare(&x->prevout, &y->prevout);
}

static int
output_compare(const void *xp, const void *yp) {
  const btc_output_t *x = *((const btc_output_t **)xp);
  const btc_output_t *y = *((const btc_output_t **)yp);

  return btc_output_compare(x, y);
}

void
btc_tx_sort(btc_tx_t *tx) {
  qsort(tx->inputs.items,
        tx->inputs.length,
        sizeof(btc_input_t *),
        input_compare);

  qsort(tx->outputs.items,
        tx->outputs.length,
        sizeof(btc_output_t *),
        output_compare);
}

size_t
btc_tx_base_size(const btc_tx_t *tx) {
  size_t size = 0;

  size += 4;
  size += btc_inpvec_size(&tx->inputs);
  size += btc_outvec_size(&tx->outputs);
  size += 4;

  return size;
}

size_t
btc_tx_witness_size(const btc_tx_t *tx) {
  size_t size = 0;
  size_t i;

  if (btc_tx_has_witness(tx)) {
    size += 2;

    for (i = 0; i < tx->inputs.length; i++)
      size += btc_stack_size(&tx->inputs.items[i]->witness);
  }

  return size;
}

size_t
btc_tx_size(const btc_tx_t *tx) {
  return btc_tx_base_size(tx) + btc_tx_witness_size(tx);
}

size_t
btc_tx_weight(const btc_tx_t *tx) {
  size_t base = btc_tx_base_size(tx);
  size_t wit = btc_tx_witness_size(tx);
  return (base * BTC_WITNESS_SCALE_FACTOR) + wit;
}

size_t
btc_tx_virtual_size(const btc_tx_t *tx) {
  size_t weight = btc_tx_weight(tx);
  return (weight + BTC_WITNESS_SCALE_FACTOR - 1) / BTC_WITNESS_SCALE_FACTOR;
}

size_t
btc_tx_sigops_size(const btc_tx_t *tx, int sigops) {
  size_t weight = btc_tx_weight(tx);

  sigops *= BTC_BYTES_PER_SIGOP;

  if ((size_t)sigops > weight)
    weight = sigops;

  return (weight + BTC_WITNESS_SCALE_FACTOR - 1) / BTC_WITNESS_SCALE_FACTOR;
}

uint8_t *
btc_tx_base_write(uint8_t *zp, const btc_tx_t *tx) {
  zp = btc_uint32_write(zp, tx->version);
  zp = btc_inpvec_write(zp, &tx->inputs);
  zp = btc_outvec_write(zp, &tx->outputs);
  zp = btc_uint32_write(zp, tx->locktime);
  return zp;
}

uint8_t *
btc_tx_write(uint8_t *zp, const btc_tx_t *tx) {
  int witness = btc_tx_has_witness(tx);
  size_t i;

  zp = btc_uint32_write(zp, tx->version);

  if (witness) {
    zp = btc_uint8_write(zp, 0);
    zp = btc_uint8_write(zp, 1);
  }

  zp = btc_inpvec_write(zp, &tx->inputs);
  zp = btc_outvec_write(zp, &tx->outputs);

  if (witness) {
    for (i = 0; i < tx->inputs.length; i++)
      zp = btc_stack_write(zp, &tx->inputs.items[i]->witness);
  }

  zp = btc_uint32_write(zp, tx->locktime);

  return zp;
}

int
btc_tx_read(btc_tx_t *z, const uint8_t **xp, size_t *xn) {
  const uint8_t *sp = *xp;
  unsigned int flags = 0;
  int witness = 0;
  size_t i;

  if (!btc_uint32_read(&z->version, xp, xn))
    return 0;

  if (*xn >= 2 && (*xp)[0] == 0 && (*xp)[1] != 0) {
    flags = (*xp)[1];
    *xp += 2;
    *xn -= 2;
  }

  if (!btc_inpvec_read(&z->inputs, xp, xn))
    return 0;

  if (!btc_outvec_read(&z->outputs, xp, xn))
    return 0;

  if (flags & 1) {
    flags ^= 1;

    for (i = 0; i < z->inputs.length; i++) {
      if (!btc_stack_read(&z->inputs.items[i]->witness, xp, xn))
        return 0;
    }

    if (!btc_tx_has_witness(z))
      return 0;

    witness = 1;
  }

  if (flags != 0)
    return 0;

  if (!btc_uint32_read(&z->locktime, xp, xn))
    return 0;

  if (witness) {
    btc_tx_txid(z->hash, z);
    btc_hash256(z->whash, sp, *xp - sp);
  } else {
    btc_hash256(z->hash, sp, *xp - sp);
    btc_hash_copy(z->whash, z->hash);
  }

  return 1;
}

int
btc_tx_base_read(btc_tx_t *z, const uint8_t **xp, size_t *xn) {
  const uint8_t *sp = *xp;

  if (!btc_uint32_read(&z->version, xp, xn))
    return 0;

  if (!btc_inpvec_read(&z->inputs, xp, xn))
    return 0;

  if (!btc_outvec_read(&z->outputs, xp, xn))
    return 0;

  if (!btc_uint32_read(&z->locktime, xp, xn))
    return 0;

  btc_hash256(z->hash, sp, *xp - sp);
  btc_hash_copy(z->whash, z->hash);

  return 1;
}

int
btc_tx_base_import(btc_tx_t *z, const uint8_t *xp, size_t xn) {
  return btc_tx_base_read(z, &xp, &xn);
}

btc_tx_t *
btc_tx_base_decode(const uint8_t *xp, size_t xn) {
  btc_tx_t *tx = btc_tx_create();

  if (!btc_tx_base_import(tx, xp, xn)) {
    btc_tx_destroy(tx);
    return NULL;
  }

  return tx;
}

/*
 * Transaction Vector
 */

DEFINE_SERIALIZABLE_VECTOR(btc_txvec, btc_tx, SCOPE_EXTERN)

size_t
btc_txvec_base_size(const btc_txvec_t *txs) {
  size_t size = 0;
  size_t i;

  size += btc_size_size(txs->length);

  for (i = 0; i < txs->length; i++)
    size += btc_tx_base_size(txs->items[i]);

  return size;
}

uint8_t *
btc_txvec_base_write(uint8_t *zp, const btc_txvec_t *x) {
  size_t i;

  zp = btc_size_write(zp, x->length);

  for (i = 0; i < x->length; i++)
    zp = btc_tx_base_write(zp, x->items[i]);

  return zp;
}

size_t
btc_txvec_witness_size(const btc_txvec_t *txs) {
  size_t size = 0;
  size_t i;

  for (i = 0; i < txs->length; i++)
    size += btc_tx_witness_size(txs->items[i]);

  return size;
}
