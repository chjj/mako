/*!
 * error.c - errors for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stddef.h>
#include <mako/error.h>
#include "internal.h"

static const struct btc_errdesc_s {
  const char *name;
  const char *reason;
  int score;
  int malleable;
} btc_errors[] = {
#define X(name, reason, score, malleable) { #name, reason, score, malleable }
  X(ERR_OK, "ok", 0, 0),
  X(ERR_BIP30, "bad-txns-BIP30", 100, 0),
  X(ERR_BLOCK_SIGOPS, "bad-blk-sigops", 100, 0),
  X(ERR_BLOCK_SIZE, "bad-blk-length", 100, 0),
  X(ERR_BLOCK_VERSION, "bad-version", 0, 0),
  X(ERR_BLOCK_WEIGHT, "bad-blk-weight", 100, 0),
  X(ERR_CB_AMOUNT, "bad-cb-amount", 100, 0),
  X(ERR_CB_HEIGHT, "bad-cb-height", 100, 0),
  X(ERR_CB_MISSING, "bad-cb-missing", 100, 0),
  X(ERR_CB_MULTIPLE, "bad-cb-multiple", 100, 0),
  X(ERR_CB_SIZE, "bad-cb-length", 100, 0),
  X(ERR_CHECKPOINT_DELTA, "time-too-old", 100, 0),
  X(ERR_CHECKPOINT_FORK, "bad-fork-prior-to-checkpoint", 100, 0),
  X(ERR_CHECKPOINT_MISMATCH, "checkpoint mismatch", 100, 0),
  X(ERR_COINBASE, "coinbase", 100, 0),
  X(ERR_DIFFBITS, "bad-diffbits", 100, 0),
  X(ERR_DUPLICATE, "duplicate", 0, 0),
  X(ERR_DUST, "dust", 0, 0),
  X(ERR_FEE_HIGH, "absurdly-high-fee", 0, 0),
  X(ERR_FEE_LOW, "insufficient fee", 0, 0),
  X(ERR_FEE_RANGE, "bad-txns-fee-outofrange", 100, 0),
  X(ERR_FINALITY, "non-final", 0, 0),
  X(ERR_HIGH_HASH, "high-hash", 50, 0),
  X(ERR_INPUT_RANGE, "bad-txns-inputvalues-outofrange", 100, 0),
  X(ERR_INPUTS_DUPLICATE, "bad-txns-inputs-duplicate", 100, 0),
  X(ERR_INPUTS_EMPTY, "bad-txns-vin-empty", 100, 0),
  X(ERR_INPUTS_MISSING, "bad-txns-inputs-missingorspent", 100, 0),
  X(ERR_INPUTS_NONSTANDARD, "bad-txns-nonstandard-inputs", 0, 0),
  X(ERR_INPUTS_SPENT, "bad-txns-inputs-spent", 0, 0),
  X(ERR_KNOWN_INVALID, "duplicate", 100, 0),
  X(ERR_LOCKS, "bad-txns-nonfinal", 100, 0),
  X(ERR_MEMPOOL_CHAIN, "too-long-mempool-chain", 0, 0),
  X(ERR_MEMPOOL_FULL, "mempool full", 0, 0),
  X(ERR_MERKLE_ROOT, "bad-txnmrklroot", 100, 1),
  X(ERR_MULTISIG, "bare-multisig", 0, 0),
  X(ERR_NONFINAL, "bad-txns-nonfinal", 10, 0),
  X(ERR_NOTFOUND, "blk-notfound", 0, 1),
  X(ERR_NULLDATA, "multi-op-return", 0, 0),
  X(ERR_OUTPUT_RANGE, "bad-txns-outputvalues-outofrange", 100, 0),
  X(ERR_OUTPUTS_EMPTY, "bad-txns-vout-empty", 100, 0),
  X(ERR_PREMATURE_CSV, "premature-version2-tx", 0, 0),
  X(ERR_PREMATURE_SPEND, "bad-txns-premature-spend-of-coinbase", 0, 0),
  X(ERR_PREMATURE_WITNESS, "no-witness-yet", 0, 1),
  X(ERR_PREVBLK, "bad-prevblk", 10, 0),
  X(ERR_PREVOUT_NULL, "bad-txns-prevout-null", 10, 0),
  X(ERR_REPLACEMENT, "replace-by-fee", 0, 0),
  X(ERR_SCRIPT_CONSENSUS, "mandatory-script-verify-flag-failed", 100, 0),
  X(ERR_SCRIPT_POLICY, "non-mandatory-script-verify-flag", 0, 0),
  X(ERR_SCRIPTPUBKEY, "scriptpubkey", 0, 0),
  X(ERR_SCRIPTSIG_PUSH, "scriptsig-not-pushonly", 0, 0),
  X(ERR_SCRIPTSIG_SIZE, "scriptsig-size", 0, 0),
  X(ERR_TOO_NEW, "time-too-new", 0, 1),
  X(ERR_TOO_OLD, "time-too-old", 0, 0),
  X(ERR_TX_BASE, "tx-size", 0, 0),
  X(ERR_TX_DUPLICATE, "bad-txns-duplicate", 100, 1),
  X(ERR_TX_IN_MEMPOOL, "txn-already-in-mempool", 0, 0),
  X(ERR_TX_KNOWN, "txn-already-known", 0, 0),
  X(ERR_TX_SIGOPS, "bad-txns-too-many-sigops", 0, 0),
  X(ERR_TX_SIZE, "bad-txns-oversize", 100, 0),
  X(ERR_TX_VERSION, "version", 0, 0),
  X(ERR_TX_WEIGHT, "tx-size", 0, 1),
  X(ERR_WITNESS_MERKLE, "bad-witness-merkle-match", 100, 1),
  X(ERR_WITNESS_NONCE, "bad-witness-nonce-size", 100, 1),
  X(ERR_WITNESS_NONSTANDARD, "bad-witness-nonstandard", 0, 1),
  X(ERR_WITNESS_UNEXPECTED, "unexpected-witness", 100, 1)
#undef X
};

const char *
btc_error_name(btc_errno_t code) {
  if ((size_t)code >= lengthof(btc_errors))
    return "ERR_UNKNOWN";

  return btc_errors[code].name;
}

const char *
btc_error_reason(btc_errno_t code) {
  if ((size_t)code >= lengthof(btc_errors))
    return "unknown-error";

  return btc_errors[code].reason;
}

int
btc_error_score(btc_errno_t code) {
  if ((size_t)code >= lengthof(btc_errors))
    return 0;

  return btc_errors[code].score;
}

int
btc_error_malleable(btc_errno_t code) {
  if ((size_t)code >= lengthof(btc_errors))
    return 0;

  return btc_errors[code].malleable;
}
