/*!
 * block.h - block for libsatoshi
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef BTC_BLOCK_H
#define BTC_BLOCK_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "common.h"
#include "impl.h"
#include "types.h"

/*
 * Block
 */

BTC_DEFINE_SERIALIZABLE_REFOBJ(btc_block, BTC_EXTERN)

BTC_EXTERN void
btc_block_init(btc_block_t *z);

BTC_EXTERN void
btc_block_clear(btc_block_t *z);

BTC_EXTERN void
btc_block_copy(btc_block_t *z, const btc_block_t *x);

BTC_EXTERN int
btc_block_has_witness(const btc_block_t *blk);

BTC_EXTERN int
btc_block_merkle_root(uint8_t *root, const btc_block_t *blk);

BTC_EXTERN int
btc_block_witness_root(uint8_t *root, const btc_block_t *blk);

BTC_EXTERN const uint8_t *
btc_block_witness_nonce(const btc_block_t *blk);

BTC_EXTERN int
btc_block_create_commitment_hash(uint8_t *hash, const btc_block_t *blk);

BTC_EXTERN int
btc_block_get_commitment_hash(uint8_t *hash, const btc_block_t *blk);

BTC_EXTERN int
btc_block_check_body(btc_verify_error_t *err, const btc_block_t *blk);

BTC_EXTERN int32_t
btc_block_coinbase_height(const btc_block_t *blk);

BTC_EXTERN int64_t
btc_block_claimed(const btc_block_t *blk);

BTC_EXTERN size_t
btc_block_base_size(const btc_block_t *blk);

BTC_EXTERN size_t
btc_block_witness_size(const btc_block_t *blk);

BTC_EXTERN size_t
btc_block_size(const btc_block_t *blk);

BTC_EXTERN size_t
btc_block_weight(const btc_block_t *blk);

BTC_EXTERN size_t
btc_block_virtual_size(const btc_block_t *blk);

BTC_EXTERN uint8_t *
btc_block_base_write(uint8_t *zp, const btc_block_t *x);

BTC_EXTERN uint8_t *
btc_block_write(uint8_t *zp, const btc_block_t *x);

BTC_EXTERN int
btc_block_read(btc_block_t *z, const uint8_t **xp, size_t *xn);

BTC_EXTERN void
btc_block_inspect(const btc_block_t *block,
                  const btc_view_t *view,
                  const btc_network_t *network);

#ifdef __cplusplus
}
#endif

#endif /* BTC_BLOCK_H */
