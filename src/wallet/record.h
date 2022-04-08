/*!
 * record.h - wallet records for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifndef BTC_WALLET_RECORD_H_
#define BTC_WALLET_RECORD_H_

#include "types.h"

/*
 * Balance
 */

BTC_DEFINE_SERIALIZABLE_OBJECT(btc_balance, extern)

void
btc_balance_init(btc_balance_t *balance);

void
btc_balance_clear(btc_balance_t *balance);

void
btc_balance_copy(btc_balance_t *z, const btc_balance_t *x);

void
btc_balance_apply(btc_balance_t *z, const btc_balance_t *x);

void
btc_balance_unapply(btc_balance_t *z, const btc_balance_t *x);

size_t
btc_balance_size(const btc_balance_t *balance);

uint8_t *
btc_balance_write(uint8_t *zp, const btc_balance_t *x);

int
btc_balance_read(btc_balance_t *z, const uint8_t **xp, size_t *xn);

/*
 * Balance Delta
 */

void
btc_delta_init(btc_delta_t *delta);

void
btc_delta_clear(btc_delta_t *delta);

btc_balance_t *
btc_delta_get(btc_delta_t *delta, uint32_t account);

void
btc_delta_tx(btc_delta_t *delta, const btc_path_t *path, int64_t value);

void
btc_delta_coin(btc_delta_t *delta, const btc_path_t *path, int64_t value);

void
btc_delta_unconf(btc_delta_t *delta, const btc_path_t *path, int64_t value);

void
btc_delta_conf(btc_delta_t *delta, const btc_path_t *path, int64_t value);

/*
 * BIP32 Serialization
 */

size_t
btc_bip32_size(const btc_hdnode_t *node);

uint8_t *
btc_bip32_write(uint8_t *zp, const btc_hdnode_t *x);

int
btc_bip32_read(btc_hdnode_t *z, const uint8_t **xp, size_t *xn);

/*
 * Credit
 */

size_t
btc_credit_size(const btc_coin_t *x);

uint8_t *
btc_credit_write(uint8_t *zp, const btc_coin_t *x);

int
btc_credit_read(btc_coin_t *z, const uint8_t **xp, size_t *xn);

size_t
btc_credit_export(uint8_t *zp, const btc_coin_t *x);

int
btc_credit_import(btc_coin_t *z, const uint8_t *xp, size_t xn);

void
btc_credit_encode(uint8_t **zp, size_t *zn, const btc_coin_t *x);

btc_coin_t *
btc_credit_decode(const uint8_t *xp, size_t xn);

/*
 * Path
 */

BTC_DEFINE_SERIALIZABLE_OBJECT(btc_path, extern)

btc_path_t
btc_path(uint32_t account, uint32_t change, uint32_t index);

void
btc_path_init(btc_path_t *path);

void
btc_path_clear(btc_path_t *path);

void
btc_path_copy(btc_path_t *z, const btc_path_t *x);

size_t
btc_path_size(const btc_path_t *path);

uint8_t *
btc_path_write(uint8_t *zp, const btc_path_t *path);

int
btc_path_read(btc_path_t *path, const uint8_t **xp, size_t *xn);

/*
 * Sync State
 */

void
btc_state_init(btc_state_t *state, const btc_network_t *network);

void
btc_state_set(btc_state_t *state, const btc_entry_t *entry);

size_t
btc_state_size(const btc_state_t *state);

uint8_t *
btc_state_write(uint8_t *zp, const btc_state_t *x);

int
btc_state_read(btc_state_t *z, const uint8_t **xp, size_t *xn);

size_t
btc_state_export(uint8_t *zp, const btc_state_t *x);

int
btc_state_import(btc_state_t *z, const uint8_t *xp, size_t xn);

/*
 * Transaction Metadata
 */

void
btc_txmeta_init(btc_txmeta_t *meta);

void
btc_txmeta_set(btc_txmeta_t *meta,
               uint64_t id,
               const btc_entry_t *entry,
               int32_t index);

void
btc_txmeta_set_block(btc_txmeta_t *meta,
                     const btc_entry_t *entry,
                     int32_t index);

size_t
btc_txmeta_size(const btc_txmeta_t *txmeta);

uint8_t *
btc_txmeta_write(uint8_t *zp, const btc_txmeta_t *x);

int
btc_txmeta_read(btc_txmeta_t *z, const uint8_t **xp, size_t *xn);

size_t
btc_txmeta_export(uint8_t *zp, const btc_txmeta_t *x);

int
btc_txmeta_import(btc_txmeta_t *z, const uint8_t *xp, size_t xn);

#endif /* BTC_WALLET_RECORD_H_ */
