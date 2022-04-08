/*!
 * master.h - wallet master key for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifndef BTC_WALLET_MASTER_H_
#define BTC_WALLET_MASTER_H_

#include "types.h"

/*
 * Constants
 */

enum {
  BTC_KDF_NONE = 0,
  BTC_KDF_PBKDF2 = 1,
  BTC_KDF_SCRYPT = 2
};

/*
 * Master Key
 */

void
btc_master_init(btc_master_t *key, const btc_network_t *network);

void
btc_master_clear(btc_master_t *key);

void
btc_master_reset(btc_master_t *key);

size_t
btc_master_size(const btc_master_t *key);

uint8_t *
btc_master_write(uint8_t *zp, const btc_master_t *x);

int
btc_master_read(btc_master_t *z, const uint8_t **xp, size_t *xn);

size_t
btc_master_export(uint8_t *zp, const btc_master_t *x);

int
btc_master_import(btc_master_t *z, const uint8_t *xp, size_t xn);

int
btc_master_encrypt(btc_master_t *key, uint8_t algorithm, const char *pass);

void
btc_master_lock(btc_master_t *key);

void
btc_master_maybe_lock(btc_master_t *key);

int
btc_master_unlock(btc_master_t *key, const char *pass, int64_t msec);

void
btc_master_generate(btc_master_t *key, enum btc_bip32_type type);

int
btc_master_import_mnemonic(btc_master_t *key,
                           enum btc_bip32_type type,
                           const btc_mnemonic_t *mnemonic);

void
btc_master_import_chain(btc_master_t *key, const btc_hdnode_t *node);

int
btc_master_account(btc_hdnode_t *node,
                   const btc_master_t *key,
                   uint32_t account);

int
btc_master_leaf(btc_hdnode_t *leaf,
                const btc_master_t *key,
                const btc_path_t *path);

#endif /* BTC_WALLET_MASTER_H_ */
