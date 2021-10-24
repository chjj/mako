/*!
 * bip37.h - bip37 for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef BTC_BIP37_H
#define BTC_BIP37_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "types.h"
#include "common.h"
#include "impl.h"

/*
 * Types
 */

typedef struct btc_merkleblock_s {
  btc_header_t header;
  uint32_t total;
  btc_vector_t hashes;
  btc_buffer_t flags;
  btc_vector_t matches;
  btc_array_t indices;
} btc_merkleblock_t;

/*
 * Merkle Block
 */

BTC_DEFINE_SERIALIZABLE_OBJECT(btc_merkleblock, BTC_EXTERN)

BTC_EXTERN void
btc_merkleblock_init(btc_merkleblock_t *z);

BTC_EXTERN void
btc_merkleblock_clear(btc_merkleblock_t *z);

BTC_EXTERN void
btc_merkleblock_copy(btc_merkleblock_t *z, const btc_merkleblock_t *x);

BTC_EXTERN size_t
btc_merkleblock_size(const btc_merkleblock_t *block);

BTC_EXTERN uint8_t *
btc_merkleblock_write(uint8_t *zp, const btc_merkleblock_t *x);

BTC_EXTERN int
btc_merkleblock_read(btc_merkleblock_t *z, const uint8_t **xp, size_t *xn);

BTC_EXTERN int
btc_merkleblock_verify(btc_merkleblock_t *block);

BTC_EXTERN btc_vector_t *
btc_merkleblock_set_block(btc_merkleblock_t *tree,
                          const btc_block_t *block,
                          btc_bloom_t *filter);

BTC_EXTERN void
btc_merkleblock_set_hashes(btc_merkleblock_t *tree,
                           const btc_block_t *block,
                           const btc_vector_t *hashes);

#ifdef __cplusplus
}
#endif

#endif /* BTC_BIP37_H */
