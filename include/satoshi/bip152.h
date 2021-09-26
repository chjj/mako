/*!
 * bip152.h - compact blocks for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef BTC_BIP152_H
#define BTC_BIP152_H

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

struct btc_mempool_s;

typedef struct btc_idvec_s {
  uint64_t *items;
  size_t alloc;
  size_t length;
} btc_idvec_t;

typedef struct btc_cmpct_s {
  uint8_t hash[32];
  btc_header_t header;
  uint64_t key_nonce;
  btc_idvec_t ids;
  btc_txvec_t ptx;
  btc_vector_t avail;
  btc_longtab_t *id_map;
  size_t count;
  uint8_t sipkey[32];
  int64_t now;
} btc_cmpct_t;

typedef struct btc_getblocktxn_s {
  uint8_t hash[32];
  btc_idvec_t indexes;
} btc_getblocktxn_t;

typedef struct btc_blocktxn_s {
  uint8_t hash[32];
  btc_txvec_t txs;
} btc_blocktxn_t;

/*
 * Compact Block
 */

BTC_DEFINE_SERIALIZABLE_OBJECT(btc_cmpct, BTC_EXTERN)

BTC_EXTERN void
btc_cmpct_init(btc_cmpct_t *z);

BTC_EXTERN void
btc_cmpct_clear(btc_cmpct_t *z);

BTC_EXTERN void
btc_cmpct_copy(btc_cmpct_t *z, const btc_cmpct_t *x);

BTC_EXTERN uint64_t
btc_cmpct_sid(const btc_cmpct_t *blk, const uint8_t *hash);

BTC_EXTERN void
btc_cmpct_set_block(btc_cmpct_t *z, const btc_block_t *x, int witness);

BTC_EXTERN int
btc_cmpct_setup(btc_cmpct_t *blk);

BTC_EXTERN int
btc_cmpct_fill_mempool(btc_cmpct_t *blk, struct btc_mempool_s *mp, int witness);

BTC_EXTERN int
btc_cmpct_fill_missing(btc_cmpct_t *blk, const btc_blocktxn_t *msg);

BTC_EXTERN void
btc_cmpct_finalize(btc_block_t *z, btc_cmpct_t *x);

BTC_EXTERN size_t
btc_cmpct_base_size(const btc_cmpct_t *blk);

BTC_EXTERN uint8_t *
btc_cmpct_base_write(uint8_t *zp, const btc_cmpct_t *x);

BTC_EXTERN size_t
btc_cmpct_size(const btc_cmpct_t *blk);

BTC_EXTERN uint8_t *
btc_cmpct_write(uint8_t *zp, const btc_cmpct_t *x);

BTC_EXTERN int
btc_cmpct_read(btc_cmpct_t *z, const uint8_t **xp, size_t *xn);

/*
 * TX Request
 */

BTC_DEFINE_SERIALIZABLE_OBJECT(btc_getblocktxn, BTC_EXTERN)

BTC_EXTERN void
btc_getblocktxn_init(btc_getblocktxn_t *z);

BTC_EXTERN void
btc_getblocktxn_clear(btc_getblocktxn_t *z);

BTC_EXTERN void
btc_getblocktxn_copy(btc_getblocktxn_t *z, const btc_getblocktxn_t *x);

BTC_EXTERN void
btc_getblocktxn_set_cmpct(btc_getblocktxn_t *z, const btc_cmpct_t *x);

BTC_EXTERN size_t
btc_getblocktxn_size(const btc_getblocktxn_t *x);

BTC_EXTERN uint8_t *
btc_getblocktxn_write(uint8_t *zp, const btc_getblocktxn_t *x);

BTC_EXTERN int
btc_getblocktxn_read(btc_getblocktxn_t *z, const uint8_t **xp, size_t *xn);

/*
 * TX Response
 */

BTC_DEFINE_SERIALIZABLE_OBJECT(btc_blocktxn, BTC_EXTERN)

BTC_EXTERN void
btc_blocktxn_init(btc_blocktxn_t *z);

BTC_EXTERN void
btc_blocktxn_clear(btc_blocktxn_t *z);

BTC_EXTERN void
btc_blocktxn_copy(btc_blocktxn_t *z, const btc_blocktxn_t *x);

BTC_EXTERN void
btc_blocktxn_set_block(btc_blocktxn_t *res,
                       const btc_block_t *blk,
                       const btc_getblocktxn_t *req);

BTC_EXTERN size_t
btc_blocktxn_base_size(const btc_blocktxn_t *x);

BTC_EXTERN uint8_t *
btc_blocktxn_base_write(uint8_t *zp, const btc_blocktxn_t *x);

BTC_EXTERN size_t
btc_blocktxn_size(const btc_blocktxn_t *x);

BTC_EXTERN uint8_t *
btc_blocktxn_write(uint8_t *zp, const btc_blocktxn_t *x);

BTC_EXTERN int
btc_blocktxn_read(btc_blocktxn_t *z, const uint8_t **xp, size_t *xn);

#ifdef __cplusplus
}
#endif

#endif /* BTC_BIP152_H */
