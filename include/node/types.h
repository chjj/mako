/*!
 * types.h - node types for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef BTC_NODE_TYPES_H
#define BTC_NODE_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/*
 * Types
 */

struct btc_network_s;
struct btc_loop_s;

typedef struct btc_addrman_s btc_addrman_t;

typedef struct btc_deployment_state_s {
  unsigned int flags;
  unsigned int lock_flags;
  int bip34;
  int bip91;
  int bip148;
} btc_deployment_state_t;

typedef struct btc_chain_s btc_chain_t;

typedef struct btc_logger_s btc_logger_t;

typedef struct btc_timedata_s {
  int64_t samples[200];
  size_t length;
  int64_t offset;
  int checked;
} btc_timedata_t;

typedef struct btc_pool_s btc_pool_t;

typedef struct btc_mempool_s btc_mempool_t;

typedef struct btc_miner_s btc_miner_t;

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
  btc_rpc_t *rpc;
} btc_node_t;

#ifdef __cplusplus
}
#endif

#endif /* BTC_NODE_TYPES_H */
