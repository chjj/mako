/*!
 * types.h - node types for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifndef BTC_NODE_TYPES_H
#define BTC_NODE_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "../base/types.h"

/*
 * Flags
 */

enum btc_node_flags {
  /*
   * Chain
   */
  BTC_CHAIN_CHECKPOINTS = 1 << 0,
  BTC_CHAIN_PRUNE = 1 << 1,
  BTC_CHAIN_DEFAULT_FLAGS = BTC_CHAIN_CHECKPOINTS,

  /*
   * Mempool
   */
  BTC_MEMPOOL_PARANOID = 1 << 2,
  BTC_MEMPOOL_PERSISTENT = 1 << 3,
  BTC_MEMPOOL_DEFAULT_FLAGS = 0,

  /*
   * Pool
   */
  BTC_POOL_LISTEN = 1 << 4,
  BTC_POOL_CHECKPOINTS = 1 << 5,
  BTC_POOL_NOCONNECT = 1 << 6,
  BTC_POOL_CONNECT = 1 << 7,
  BTC_POOL_PROXY = 1 << 8,
  BTC_POOL_DISCOVER = 1 << 9,
  BTC_POOL_UPNP = 1 << 10,
  BTC_POOL_ONION = 1 << 11,
  BTC_POOL_BLOCKSONLY = 1 << 12,
  BTC_POOL_BIP37 = 1 << 13,
  BTC_POOL_BIP152 = 1 << 14,
  BTC_POOL_BIP157 = 1 << 15,
  BTC_POOL_DEFAULT_FLAGS = BTC_POOL_LISTEN
                         | BTC_POOL_CHECKPOINTS
                         | BTC_POOL_DISCOVER
                         | BTC_POOL_BIP152,

  /*
   * Miner
   */
  BTC_MINER_DEFAULT_FLAGS = 0,

  /*
   * RPC
   */
  BTC_RPC_DEFAULT_FLAGS = 0
};

/*
 * Types
 */

struct btc_network_s;
struct btc_loop_s;

typedef struct btc_deployment_state_s {
  unsigned int flags;
  unsigned int lock_flags;
  int bip34;
  int bip91;
  int bip148;
} btc_deployment_state_t;

typedef struct btc_chaindb_s btc_chaindb_t;
typedef struct btc_chain_s btc_chain_t;

typedef struct btc_pool_s btc_pool_t;

typedef struct btc_mempool_s btc_mempool_t;

typedef struct btc_miner_s btc_miner_t;

struct btc_wallet_s;

typedef struct btc_rpc_s btc_rpc_t;

typedef struct btc_node_s {
  const struct btc_network_s *network;
  struct btc_loop_s *loop;
  btc_logger_t *logger;
  btc_timedata_t *timedata;
  btc_chain_t *chain;
  btc_mempool_t *mempool;
  btc_miner_t *miner;
  btc_pool_t *pool;
  struct btc_wallet_s *wallet;
  btc_rpc_t *rpc;
} btc_node_t;

#ifdef __cplusplus
}
#endif

#endif /* BTC_NODE_TYPES_H */
