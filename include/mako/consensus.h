/*!
 * consensus.h - consensus for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifndef BTC_CONSENSUS_H
#define BTC_CONSENSUS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "common.h"

/**
 * One bitcoin in satoshis.
 */

#define BTC_COIN INT64_C(100000000)

/**
 * Maximum amount of money in satoshis:
 * `21million * 1btc` (consensus).
 */

#define BTC_MAX_MONEY (INT64_C(21000000) * BTC_COIN)

/**
 * Base block subsidy (consensus).
 * Note to shitcoin implementors: if you
 * increase this to anything greater than
 * 33 bits, getReward will have to be
 * modified to handle the shifts.
 */

#define BTC_BASE_REWARD (INT64_C(50) * BTC_COIN)

/**
 * Maximum block base size (consensus).
 */

#define BTC_MAX_BLOCK_SIZE 1000000

/**
 * Maximum block serialization size (protocol).
 */

#define BTC_MAX_RAW_BLOCK_SIZE 4000000

/**
 * Maximum block weight (consensus).
 */

#define BTC_MAX_BLOCK_WEIGHT 4000000

/**
 * Maximum block sigops (consensus).
 */

#define BTC_MAX_BLOCK_SIGOPS (1000000 / 50)

/**
 * Maximum block sigops cost (consensus).
 */

#define BTC_MAX_BLOCK_SIGOPS_COST 80000

/**
 * Size of set to pick median time from.
 */

#define BTC_MEDIAN_TIMESPAN 11

/**
 * What bits to set in version
 * for versionbits blocks.
 */

#define BTC_VERSION_TOP_BITS UINT32_C(0x20000000)

/**
 * What bitmask determines whether
 * versionbits is in use.
 */

#define BTC_VERSION_TOP_MASK UINT32_C(0xe0000000)

/**
 * Number of blocks before a coinbase
 * spend can occur (consensus).
 */

#define BTC_COINBASE_MATURITY 100

/**
 * Amount to multiply base/non-witness sizes by.
 */

#define BTC_WITNESS_SCALE_FACTOR 4

/**
 * nLockTime threshold for differentiating
 * between height and time (consensus).
 * Tue Nov 5 00:53:20 1985 UTC
 */

#define BTC_LOCKTIME_THRESHOLD UINT32_C(500000000)

/**
 * Highest nSequence bit -- disables
 * sequence locktimes (consensus).
 */

#define BTC_SEQUENCE_DISABLE_FLAG (UINT32_C(1) << 31)

/**
 * Sequence time: height or time (consensus).
 */

#define BTC_SEQUENCE_TYPE_FLAG (UINT32_C(1) << 22)

/**
 * Sequence granularity for time (consensus).
 */

#define BTC_SEQUENCE_GRANULARITY 9

/**
 * Sequence mask (consensus).
 */

#define BTC_SEQUENCE_MASK UINT32_C(0x0000ffff)

/**
 * Max serialized script size (consensus).
 */

#define BTC_MAX_SCRIPT_SIZE 10000

/**
 * Max stack size during execution (consensus).
 */

#define BTC_MAX_SCRIPT_STACK 1000

/**
 * Max script element size (consensus).
 */

#define BTC_MAX_SCRIPT_PUSH 520

/**
 * Max opcodes executed (consensus).
 */

#define BTC_MAX_SCRIPT_OPS 201

/**
 * Max `n` value for multisig (consensus).
 */

#define BTC_MAX_MULTISIG_PUBKEYS 20

/**
 * The date bip16 (p2sh) was activated (consensus).
 */

#define BTC_BIP16_TIME INT64_C(1333238400)

/*
 * Helpers
 */

BTC_EXTERN int
btc_has_versionbit(uint32_t version, int bit);

BTC_EXTERN int64_t
btc_get_reward(int32_t height, int32_t interval);

#ifdef __cplusplus
}
#endif

#endif /* BTC_CONSENSUS_H */
