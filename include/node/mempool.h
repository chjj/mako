/*!
 * mempool.h - mempool for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifndef BTC_MEMPOOL_H
#define BTC_MEMPOOL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "types.h"
#include "../mako/common.h"
#include "../mako/impl.h"
#include "../mako/types.h"

/*
 * Types
 */

typedef void btc_mempool_tx_cb(const btc_mpentry_t *entry,
                               const btc_view_t *view,
                               void *arg);

typedef void btc_mempool_badorphan_cb(const btc_verify_error_t *err,
                                      unsigned int id,
                                      void *arg);

/*
 * Mempool
 */

BTC_EXTERN btc_mempool_t *
btc_mempool_create(const btc_network_t *network, btc_chain_t *chain);

BTC_EXTERN void
btc_mempool_destroy(btc_mempool_t *mp);

BTC_EXTERN void
btc_mempool_set_logger(btc_mempool_t *mp, btc_logger_t *logger);

BTC_EXTERN void
btc_mempool_set_timedata(btc_mempool_t *mp, const btc_timedata_t *td);

BTC_EXTERN void
btc_mempool_on_tx(btc_mempool_t *mp, btc_mempool_tx_cb *handler);

BTC_EXTERN void
btc_mempool_on_badorphan(btc_mempool_t *mp,
                         btc_mempool_badorphan_cb *handler);

BTC_EXTERN void
btc_mempool_set_context(btc_mempool_t *mp, void *arg);

BTC_EXTERN int
btc_mempool_open(btc_mempool_t *mp, const char *prefix, unsigned int flags);

BTC_EXTERN void
btc_mempool_close(btc_mempool_t *mp);

BTC_EXTERN btc_view_t *
btc_mempool_view(btc_mempool_t *mp, const btc_tx_t *tx);

BTC_EXTERN int
btc_mempool_add(btc_mempool_t *mp,
                const btc_tx_t *tx,
                unsigned int id);

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

BTC_EXTERN const btc_verify_error_t *
btc_mempool_error(btc_mempool_t *mp);

BTC_EXTERN size_t
btc_mempool_size(btc_mempool_t *mp);

BTC_EXTERN int
btc_mempool_has(btc_mempool_t *mp, const uint8_t *hash);

BTC_EXTERN const btc_mpentry_t *
btc_mempool_get(btc_mempool_t *mp, const uint8_t *hash);

BTC_EXTERN btc_coin_t *
btc_mempool_coin(btc_mempool_t *mp, const uint8_t *hash, size_t index);

BTC_EXTERN int
btc_mempool_has_orphan(btc_mempool_t *mp, const uint8_t *hash);

BTC_EXTERN int
btc_mempool_has_reject(btc_mempool_t *mp, const uint8_t *hash);

BTC_EXTERN btc_vector_t *
btc_mempool_missing(btc_mempool_t *mp, const btc_tx_t *tx);

BTC_EXTERN const btc_hashmap_t *
btc_mempool_map(const btc_mempool_t *mp);

#ifdef __cplusplus
}
#endif

#endif /* BTC_MEMPOOL_H */
