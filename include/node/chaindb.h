/*!
 * chaindb.h - chaindb for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifndef BTC_CHAINDB_H
#define BTC_CHAINDB_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include "types.h"
#include "../mako/common.h"
#include "../mako/types.h"

/*
 * Chain Database
 */

BTC_EXTERN btc_chaindb_t *
btc_chaindb_create(const btc_network_t *network);

BTC_EXTERN void
btc_chaindb_destroy(btc_chaindb_t *db);

BTC_EXTERN void
btc_chaindb_set_cache(btc_chaindb_t *db, size_t cache_size);

BTC_EXTERN int
btc_chaindb_open(btc_chaindb_t *db, const char *prefix, unsigned int flags);

BTC_EXTERN void
btc_chaindb_close(btc_chaindb_t *db);

BTC_EXTERN btc_coin_t *
btc_chaindb_coin(btc_chaindb_t *db, const uint8_t *hash, size_t index);

BTC_EXTERN int
btc_chaindb_spend(btc_chaindb_t *db,
                  btc_view_t *view,
                  const btc_tx_t *tx);

BTC_EXTERN int
btc_chaindb_fill(btc_chaindb_t *db,
                 btc_view_t *view,
                 const btc_tx_t *tx);

BTC_EXTERN int
btc_chaindb_save(btc_chaindb_t *db,
                 btc_entry_t *entry,
                 const btc_block_t *block,
                 const btc_view_t *view);

BTC_EXTERN int
btc_chaindb_reconnect(btc_chaindb_t *db,
                      btc_entry_t *entry,
                      const btc_block_t *block,
                      const btc_view_t *view);

BTC_EXTERN btc_view_t *
btc_chaindb_disconnect(btc_chaindb_t *db,
                       btc_entry_t *entry,
                       const btc_block_t *block);

BTC_EXTERN const btc_entry_t *
btc_chaindb_head(btc_chaindb_t *db);

BTC_EXTERN const btc_entry_t *
btc_chaindb_tail(btc_chaindb_t *db);

BTC_EXTERN int32_t
btc_chaindb_height(btc_chaindb_t *db);

BTC_EXTERN const btc_entry_t *
btc_chaindb_by_hash(btc_chaindb_t *db, const uint8_t *hash);

BTC_EXTERN const btc_entry_t *
btc_chaindb_by_height(btc_chaindb_t *db, int32_t height);

BTC_EXTERN int
btc_chaindb_is_main(btc_chaindb_t *db, const btc_entry_t *entry);

BTC_EXTERN int
btc_chaindb_has_coins(btc_chaindb_t *db, const btc_tx_t *tx);

BTC_EXTERN btc_block_t *
btc_chaindb_get_block(btc_chaindb_t *db, const btc_entry_t *entry);

BTC_EXTERN int
btc_chaindb_get_raw_block(btc_chaindb_t *db,
                          uint8_t **data,
                          size_t *length,
                          const btc_entry_t *entry);

BTC_EXTERN btc_view_t *
btc_chaindb_get_undo(btc_chaindb_t *db,
                     const btc_entry_t *entry,
                     const btc_block_t *block);

#ifdef __cplusplus
}
#endif

#endif /* BTC_CHAINDB_H */
