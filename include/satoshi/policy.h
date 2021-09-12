/*!
 * policy.h - policy for libsatoshi
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef BTC_POLICY_H
#define BTC_POLICY_H

#include <stdint.h>
#include "consensus.h"

/**
 * Maximum transaction version (policy).
 */

#define BTC_MAX_TX_VERSION 2

/**
 * Maximum transaction base size (policy).
 */

#define BTC_MAX_TX_SIZE (BTC_MAX_BLOCK_SIZE / 10)

/**
 * Maximum transaction weight (policy).
 */

#define BTC_MAX_TX_WEIGHT (BTC_MAX_BLOCK_WEIGHT / 10)

/**
 * Maximum number of transaction sigops (policy).
 */

#define BTC_MAX_TX_SIGOPS (BTC_MAX_BLOCK_SIGOPS / 5)

/**
 * Maximum cost of transaction sigops (policy).
 */

#define BTC_MAX_TX_SIGOPS_COST (BTC_MAX_BLOCK_SIGOPS_COST / 5)

/**
 * How much weight a sigop should
 * add to virtual size (policy).
 */

#define BTC_BYTES_PER_SIGOP 20

/**
 * Minimum relay fee rate (policy).
 */

#define BTC_MIN_RELAY 1000

/**
 * Whether bare multisig outputs
 * should be relayed (policy).
 */

#define BTC_BARE_MULTISIG 1

/**
 * Priority threshold for
 * free transactions (policy).
 */

#define BTC_FREE_THRESHOLD (BTC_COIN * 144 / 250)

/**
 * Max sigops per redeem script (policy).
 */

#define BTC_MAX_P2SH_SIGOPS 15

/**
 * Max serialized nulldata size (policy).
 */

#define BTC_MAX_OP_RETURN_BYTES 83

/**
 * Max pushdata size in nulldata (policy).
 */

#define BTC_MAX_OP_RETURN 80

/**
 * Max p2wsh stack size. Used for
 * witness malleation checks (policy).
 */

#define BTC_MAX_P2WSH_STACK 100

/**
 * Max p2wsh push size. Used for
 * witness malleation checks (policy).
 */

#define BTC_MAX_P2WSH_PUSH 80

/**
 * Max serialized p2wsh size. Used for
 * witness malleation checks (policy).
 */

#define BTC_MAX_P2WSH_SIZE 3600

/**
 * Default ancestor limit.
 */

#define BTC_MEMPOOL_MAX_ANCESTORS 25

/**
 * Default maximum mempool size in bytes.
 */

#define BTC_MEMPOOL_MAX_SIZE (100 * 1000000)

/**
 * Time at which transactions
 * fall out of the mempool.
 */

#define BTC_MEMPOOL_EXPIRY_TIME (72 * 60 * 60)

/**
 * Maximum number of orphan transactions.
 */

#define BTC_MEMPOOL_MAX_ORPHANS 100

/**
 * Minimum block size to create. Block will be
 * filled with free transactions until block
 * reaches this weight.
 */

#define BTC_MIN_BLOCK_WEIGHT 0

/**
 * Maximum block weight to be mined.
 */

#define BTC_MAX_BLOCK_WEIGHT_ (1000000 * BTC_WITNESS_SCALE_FACTOR)

/**
 * How much of the block should be dedicated to
 * high-priority transactions (included regardless
 * of fee rate).
 */

#define BTC_BLOCK_PRIORITY_WEIGHT 0

/**
 * Priority threshold to be reached before
 * switching to fee rate comparison.
 */

#define BTC_BLOCK_PRIORITY_THRESHOLD BTC_FREE_THRESHOLD

#endif /* BTC_POLICY_H */
