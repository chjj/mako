/*!
 * chaindb.h - chaindb for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef BTC_CHAINDB_H
#define BTC_CHAINDB_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include "satoshi/common.h"
#include "satoshi/types.h"

/*
 * Types
 */

typedef struct btc_chaindb_s btc_chaindb_t;

/*
 * Chain Database
 */

BTC_EXTERN btc_chaindb_t *
btc_chaindb_create(const btc_network_t *network);

BTC_EXTERN void
btc_chaindb_destroy(btc_chaindb_t *db);

BTC_EXTERN int
btc_chaindb_open(btc_chaindb_t *db,
                 const char *prefix,
                 size_t map_size);

BTC_EXTERN void
btc_chaindb_close(btc_chaindb_t *db);

BTC_EXTERN int
btc_chaindb_spend(btc_chaindb_t *db,
                  btc_view_t *view,
                  const btc_tx_t *tx);

BTC_EXTERN int
btc_chaindb_save(btc_chaindb_t *db,
                 btc_entry_t *entry,
                 const btc_block_t *block,
                 btc_view_t *view);

BTC_EXTERN int
btc_chaindb_reconnect(btc_chaindb_t *db,
                      btc_entry_t *entry,
                      const btc_block_t *block,
                      btc_view_t *view);

BTC_EXTERN btc_view_t *
btc_chaindb_disconnect(btc_chaindb_t *db,
                       btc_entry_t *entry,
                       const btc_block_t *block);

#ifdef __cplusplus
}
#endif

#endif /* BTC_CHAINDB_H */
