/*!
 * mempool.h - mempool for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef BTC_MEMPOOL_H
#define BTC_MEMPOOL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "types.h"
#include "../satoshi/common.h"
#include "../satoshi/impl.h"
#include "../satoshi/types.h"

/*
 * Types
 */

typedef struct btc_mpentry_s {
  uint8_t hash[32];
  btc_tx_t tx;
  int32_t height;
  uint32_t size;
  uint32_t sigops;
  double priority;
  int64_t fee;
  int64_t delta_fee;
  int64_t time;
  int64_t value;
  uint8_t coinbase;
  uint8_t dependencies;
  int64_t desc_fee;
  int64_t desc_size;
} btc_mpentry_t;

typedef struct btc_mpiter_s {
  btc_mempool_t *mp;
  uint32_t it;
} btc_mpiter_t;

typedef void btc_mempool_tx_cb(const btc_mpentry_t *entry,
                               btc_view_t *view,
                               void *arg);

typedef void btc_mempool_badorphan_cb(const btc_verify_error_t *err,
                                      int id,
                                      void *arg);

/*
 * Mempool
 */

BTC_EXTERN btc_mempool_t *
btc_mempool_create(const struct btc_network_s *network, btc_chain_t *chain);

BTC_EXTERN void
btc_mempool_destroy(btc_mempool_t *mp);

BTC_EXTERN void
btc_mempool_set_logger(btc_mempool_t *mp, btc_logger_t *logger);

BTC_EXTERN void
btc_mempool_set_timedata(btc_mempool_t *mp, const btc_timedata_t *td);

BTC_EXTERN void
btc_mempool_on_tx(btc_mempool_t *mp, btc_mempool_tx_cb *handler);

BTC_EXTERN void
btc_mempool_on_badorphan(btc_mempool_t *mp, btc_mempool_badorphan_cb *handler);

BTC_EXTERN void
btc_mempool_set_context(btc_mempool_t *mp, void *arg);

BTC_EXTERN int
btc_mempool_open(btc_mempool_t *mp);

BTC_EXTERN void
btc_mempool_close(btc_mempool_t *mp);

BTC_EXTERN void
btc_mempool_add_block(btc_mempool_t *mp,
                      const btc_entry_t *entry,
                      const btc_block_t *block);

BTC_EXTERN void
btc_mempool_remove_block(btc_mempool_t *mp,
                         const btc_entry_t *entry,
                         const btc_block_t *block);

BTC_EXTERN void
btc_mempool_handle_reorg(btc_mempool_t *mp);

BTC_EXTERN int
btc_mempool_add(btc_mempool_t *mp, const btc_tx_t *tx, int id);

BTC_EXTERN int
btc_mempool_has(btc_mempool_t *mp, const uint8_t *hash);

BTC_EXTERN const btc_mpentry_t *
btc_mempool_get(btc_mempool_t *mp, const uint8_t *hash);

BTC_EXTERN int
btc_mempool_has_reject(btc_mempool_t *mp, const uint8_t *hash);

BTC_EXTERN void
btc_mempool_iterate(btc_mpiter_t *iter, btc_mempool_t *mp);

BTC_EXTERN int
btc_mempool_next(const btc_mpentry_t **entry, btc_mpiter_t *iter);

/**
 * Mempool Entry
 */

BTC_DEFINE_SERIALIZABLE_OBJECT(btc_mpentry, BTC_EXTERN)

BTC_EXTERN void
btc_mpentry_init(btc_mpentry_t *entry);

BTC_EXTERN void
btc_mpentry_clear(btc_mpentry_t *entry);

BTC_EXTERN void
btc_mpentry_copy(btc_mpentry_t *z, const btc_mpentry_t *x);

BTC_EXTERN void
btc_mpentry_set(btc_mpentry_t *z, const btc_tx_t *tx);

BTC_EXTERN size_t
btc_mpentry_size(const btc_mpentry_t *x);

BTC_EXTERN uint8_t *
btc_mpentry_write(uint8_t *zp, const btc_mpentry_t *x);

BTC_EXTERN int
btc_mpentry_read(btc_mpentry_t *z, const uint8_t **xp, size_t *xn);

#ifdef __cplusplus
}
#endif

#endif /* BTC_MEMPOOL_H */
