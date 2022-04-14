/*!
 * types.h - wallet types for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifndef BTC_WALLET_TYPES_H_
#define BTC_WALLET_TYPES_H_

#include <stddef.h>
#include <stdint.h>

#include <lcdb.h>

#include <mako/impl.h>
#include <mako/types.h>

#include <wallet/types.h>

/*
 * Types
 */

typedef struct btc_account_s {
  char name[64];
  uint32_t index;
  uint32_t receive_index;
  uint32_t change_index;
  uint32_t lookahead;
  uint8_t watch_only;
  btc_hdnode_t key;
  btc_bloom_t *filter;
} btc_account_t;

typedef struct btc_delta_s {
  btc_balance_t balance;
  btc_balance_t watched;
  btc_intmap_t map;
  int updated;
} btc_delta_t;

typedef struct btc_master_s {
  const btc_network_t *network;
  enum btc_bip32_type type;
  btc_mnemonic_t mnemonic;
  btc_hdnode_t chain;
  int locked;
  int64_t deadline;
  uint8_t algorithm;
  uint8_t nonce[24];
  uint64_t N;
  uint32_t r;
  uint32_t p;
  btc_buffer_t payload;
} btc_master_t;

typedef struct btc_state_s {
  int32_t start_height;
  uint8_t start_hash[32];
  int32_t height;
  uint8_t marked;
} btc_state_t;

typedef btc_wallet_t btc_txdb_t;

struct btc_wallet_s {
  const btc_network_t *network;
  btc_walopt_t options;
  btc_wclient_t client;
  btc_mnemonic_t mnemonic_tmp;
  btc_hdnode_t chain_tmp;
  btc_outset_t frozen;
  int64_t rate;
  ldb_t *db;
  ldb_lru_t *cache;
  btc_state_t state;
  btc_bloom_t filter;
  uint32_t account_index;
  uint32_t watch_index;
  uint64_t unique_id;
  btc_balance_t balance;
  btc_balance_t watched;
  btc_master_t master;
};

#endif /* BTC_WALLET_TYPES_H_ */
