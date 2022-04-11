/*!
 * miner.h - miner for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifndef BTC_MINER_H
#define BTC_MINER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include "types.h"
#include "../mako/common.h"
#include "../mako/impl.h"
#include "../mako/types.h"

/*
 * Types
 */

typedef struct btc_blockentry_s {
  btc_tx_t *tx;
  const uint8_t *hash;
  const uint8_t *whash;
  int64_t fee;
  int64_t rate;
  size_t weight;
  int sigops;
  int64_t desc_rate;
  int dep_count;
} btc_blockentry_t;

typedef struct btc_blockproof_s {
  uint8_t hash[32];
  uint8_t root[32];
  uint32_t nonce1;
  uint32_t nonce2;
  int64_t time;
  uint32_t nonce;
} btc_blockproof_t;

typedef struct btc_steps_s {
  uint8_t hashes[16 * 32]; /* ceil(log2(16665+1)) == 15 */
  size_t length;
} btc_steps_t;

typedef struct btc_tmpl_s {
  uint32_t version;
  uint8_t prev_block[32];
  int64_t time;
  uint32_t bits;
  int32_t height;
  int64_t mtp;
  unsigned int flags;
  int32_t interval;
  size_t weight;
  int sigops;
  int64_t fees;
  uint8_t commitment[32];
  uint32_t chain_nonce;
  btc_steps_t steps;
  btc_buffer_t cbflags;
  btc_address_t address;
  btc_vector_t txs;
} btc_tmpl_t;

/*
 * Block Template
 */

BTC_DEFINE_OBJECT(btc_tmpl, BTC_SCOPE_EXTERN)

BTC_EXTERN void
btc_tmpl_init(btc_tmpl_t *bt);

BTC_EXTERN void
btc_tmpl_clear(btc_tmpl_t *bt);

BTC_EXTERN void
btc_tmpl_copy(btc_tmpl_t *z, const btc_tmpl_t *x);

BTC_EXTERN int64_t
btc_tmpl_reward(const btc_tmpl_t *bt);

BTC_EXTERN int
btc_tmpl_witness(const btc_tmpl_t *bt);

BTC_EXTERN int64_t
btc_tmpl_locktime(const btc_tmpl_t *bt);

BTC_EXTERN void
btc_tmpl_refresh(btc_tmpl_t *bt);

BTC_EXTERN btc_tx_t *
btc_tmpl_coinbase(const btc_tmpl_t *bt, uint32_t nonce1, uint32_t nonce2);

BTC_EXTERN void
btc_tmpl_compute(uint8_t *root, const btc_tmpl_t *bt, const uint8_t *hash);

BTC_EXTERN void
btc_tmpl_root(uint8_t *root,
              const btc_tmpl_t *bt,
              uint32_t nonce1,
              uint32_t nonce2);

BTC_EXTERN void
btc_tmpl_header(btc_header_t *hdr,
                const btc_tmpl_t *bt,
                const uint8_t *root,
                int64_t time,
                uint32_t nonce);

BTC_EXTERN int
btc_tmpl_prove(btc_blockproof_t *proof,
               const btc_tmpl_t *bt,
               uint32_t nonce1,
               uint32_t nonce2,
               int64_t time,
               uint32_t nonce);

BTC_EXTERN btc_block_t *
btc_tmpl_commit(const btc_tmpl_t *bt, const btc_blockproof_t *proof);

BTC_EXTERN void
btc_tmpl_getwork(btc_header_t *hdr,
                 const btc_tmpl_t *bt,
                 uint32_t nonce1,
                 uint32_t nonce2);

BTC_EXTERN btc_block_t *
btc_tmpl_submitwork(const btc_tmpl_t *bt,
                    const btc_header_t *hdr,
                    uint32_t nonce1,
                    uint32_t nonce2);

BTC_EXTERN btc_block_t *
btc_tmpl_mine(const btc_tmpl_t *bt);

BTC_EXTERN void
btc_tmpl_push(btc_tmpl_t *bt, const btc_tx_t *tx, const btc_view_t *view);

BTC_EXTERN int
btc_tmpl_add(btc_tmpl_t *bt, const btc_tx_t *tx, const btc_view_t *view);

/*
 * Miner
 */

BTC_EXTERN btc_miner_t *
btc_miner_create(const btc_network_t *network,
                 struct btc_loop_s *loop,
                 btc_chain_t *chain,
                 btc_mempool_t *mempool);

BTC_EXTERN void
btc_miner_destroy(btc_miner_t *miner);

BTC_EXTERN void
btc_miner_set_logger(btc_miner_t *miner, btc_logger_t *logger);

BTC_EXTERN void
btc_miner_set_timedata(btc_miner_t *miner, const btc_timedata_t *td);

BTC_EXTERN int
btc_miner_open(btc_miner_t *miner, unsigned int flags);

BTC_EXTERN void
btc_miner_close(btc_miner_t *miner);

BTC_EXTERN void
btc_miner_add_address(btc_miner_t *miner, const btc_address_t *addr);

BTC_EXTERN void
btc_miner_get_address(btc_miner_t *miner, btc_address_t *addr);

BTC_EXTERN void
btc_miner_set_data(btc_miner_t *miner, const uint8_t *flags, size_t length);

BTC_EXTERN void
btc_miner_set_flags(btc_miner_t *miner, const char *flags);

BTC_EXTERN void
btc_miner_update_time(btc_miner_t *miner, btc_tmpl_t *bt);

BTC_EXTERN btc_tmpl_t *
btc_miner_template(btc_miner_t *miner);

BTC_EXTERN int
btc_miner_getgenerate(btc_miner_t *miner);

BTC_EXTERN void
btc_miner_setgenerate(btc_miner_t *miner, int value, int active);

BTC_EXTERN void
btc_miner_generate(btc_miner_t *miner, int blocks, const btc_address_t *addr);

#ifdef __cplusplus
}
#endif

#endif /* BTC_MINER_H */
