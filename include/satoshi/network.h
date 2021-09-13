/*!
 * network.h - network for libsatoshi
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef BTC_NETWORK_H
#define BTC_NETWORK_H

#include <stddef.h>
#include <stdint.h>
#include "common.h"
#include "types.h"

enum btc_network {
  BTC_NETWORK_MAINNET,
  BTC_NETWORK_TESTNET,
  BTC_NETWORK_REGTEST,
  BTC_NETWORK_SIMNET
};

typedef struct btc_checkpoint_s {
  uint32_t height;
  uint8_t hash[32];
} btc_checkpoint_t;

typedef struct btc_deployment_s {
  const char *name;
  int bit;
  uint32_t start_time;
  uint32_t timeout;
  int threshold;
  int window;
  int required;
  int force;
} btc_deployment_t;

typedef struct btc_network_s {
  /**
   * Network type.
   */
  enum btc_network type;

  /**
   * Symbolic network name.
   */
  const char *name;

  /**
   * Default DNS seeds.
   */
  struct btc_network_seeds_s {
    const char **items;
    size_t length;
  } seeds;

  /**
   * Packet magic number.
   */
  uint32_t magic;

  /**
   * Default network port.
   */
  int port;

  /**
   * Checkpoint list.
   */
  struct btc_network_checkpoints_s {
    const btc_checkpoint_t *items;
    size_t length;
  } checkpoints;

  /**
   * Block subsidy halving interval.
   */
  uint32_t halving_interval;

  /**
   * Genesis block.
   */
  struct btc_network_genesis_s {
    uint8_t hash[32];
    btc_header_t header;
    const uint8_t *data;
    size_t length;
  } genesis;

  /**
   * POW-related constants.
   */
  struct btc_network_pow_s {
    /**
     * Default target.
     */
    uint8_t limit[32];

    /**
     * Compact pow limit.
     */
    uint32_t bits;

    /**
     * Minimum chainwork for best chain.
     */
    uint8_t chainwork[32];

    /**
     * Desired retarget period in seconds.
     */
    uint32_t target_timespan;

    /**
     * Average block time.
     */
    uint32_t target_spacing;

    /**
     * Retarget interval in blocks.
     */
    uint32_t retarget_interval;

    /**
     * Whether to reset target if a block
     * has not been mined recently.
     */
    int target_reset;

    /**
     * Do not allow retargetting.
     */
    int no_retargeting;
  } pow;

  /**
   * Block constants.
   */
  struct btc_network_block_s {
    /**
     * Safe height to start pruning.
     */
    uint32_t prune_after_height;

    /**
     * Safe number of blocks to keep.
     */
    uint32_t keep_blocks;

    /**
     * Age used for the time delta to
     * determine whether the chain is synced.
     */
    uint32_t max_tip_age;

    /**
     * Height at which block processing is
     * slow enough that we can output
     * logs without spamming.
     */
    uint32_t slow_height;
  } block;

  /**
   * Pre-versionbit soft-forks.
   */
  struct btc_network_softforks_s {
    /**
     * Map of historical blocks which create duplicate transactions hashes.
     * See: https://github.com/bitcoin/bips/blob/master/bip-0030.mediawiki
     */
    struct btc_network_bip30_s {
      const btc_checkpoint_t *items;
      size_t length;
    } bip30;

    /**
     * Block which activated bip34.
     * Used for avoiding bip30 checks.
     */
    btc_checkpoint_t bip34;

    /**
     * Block which activated bip65.
     */
    btc_checkpoint_t bip65;

    /**
     * Block which activated bip66.
     */
    btc_checkpoint_t bip66;
  } softforks;

  /**
   * Version bits activation threshold.
   */
  uint32_t activation_threshold;

  /**
   * Confirmation window for versionbits.
   */
  uint32_t miner_window;

  /**
   * Deployments for versionbits.
   */
  struct btc_network_deployments_s {
    const btc_deployment_t *items;
    size_t length;
  } deployments;

  /**
   * Key prefixes.
   */
  struct btc_network_key_s {
    uint8_t privkey;
    uint32_t xpubkey;
    uint32_t xprivkey;
    const char *xpubkey58;
    const char *xprivkey58;
    int coin_type;
  } key;

  /**
   * Address prefixes.
   */
  struct btc_network_address_s {
    uint8_t p2pkh;
    uint8_t p2sh;
    const char *bech32;
  } address;

  /**
   * Default value for whether the mempool
   * accepts non-standard transactions.
   */
  int require_standard;

  /**
   * Default rpc port.
   */
  int rpc_port;

  /**
   * Default min relay rate.
   */
  int64_t min_relay;

  /**
   * Default normal relay rate.
   */
  int64_t fee_rate;

  /**
   * Maximum normal relay rate.
   */
  int64_t max_fee_rate;

  /**
   * Whether to allow self-connection.
   */
  int self_connect;

  /**
   * Whether to request mempool on sync.
   */
  int request_mempool;
} btc_network_t;

extern const btc_network_t *btc_main;

#endif /* BTC_NETWORK_H */
