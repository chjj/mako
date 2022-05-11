/*!
 * txdb.h - wallet txdb for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifndef BTC_WALLET_TXDB_H_
#define BTC_WALLET_TXDB_H_

#include "types.h"

/*
 * TXDB
 */

int
btc_txdb_add(btc_txdb_t *txdb,
             const btc_tx_t *tx,
             const btc_entry_t *entry,
             int32_t index);

int
btc_txdb_remove(btc_txdb_t *txdb, const uint8_t *hash);

int
btc_txdb_abandon(btc_txdb_t *txdb, const uint8_t *hash);

int
btc_txdb_revert(btc_txdb_t *txdb, int32_t height);

int
btc_txdb_fill(btc_txdb_t *txdb, btc_view_t *view, const btc_tx_t *tx);

btc_view_t *
btc_txdb_undo(btc_txdb_t *txdb, const btc_tx_t *tx);

#endif /* BTC_WALLET_TXDB_H_ */
