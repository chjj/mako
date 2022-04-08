/*!
 * account.h - wallet account for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifndef BTC_WALLET_ACCOUNT_H_
#define BTC_WALLET_ACCOUNT_H_

#include "types.h"

/*
 * Account
 */

void
btc_account_init(btc_account_t *acct, btc_bloom_t *filter);

void
btc_account_clear(btc_account_t *acct);

size_t
btc_account_size(const btc_account_t *acct);

uint8_t *
btc_account_write(uint8_t *zp, const btc_account_t *x);

int
btc_account_read(btc_account_t *z, const uint8_t **xp, size_t *xn);

size_t
btc_account_export(uint8_t *zp, const btc_account_t *x);

int
btc_account_import(btc_account_t *z, const uint8_t *xp, size_t xn);

int
btc_account_import_name(char *name, size_t size, const uint8_t *xp, size_t xn);

void
btc_account_leaf(btc_hdnode_t *leaf,
                 const btc_account_t *acct,
                 uint32_t change,
                 uint32_t index);

void
btc_account_address(btc_address_t *addr,
                    const btc_account_t *acct,
                    uint32_t change,
                    uint32_t index);

void
btc_account_receive(btc_address_t *addr, const btc_account_t *acct);

void
btc_account_change(btc_address_t *addr, const btc_account_t *acct);

void
btc_account_path(const btc_account_t *acct,
                 ldb_batch_t *batch,
                 uint32_t change,
                 uint32_t index);

void
btc_account_setup(const btc_account_t *acct, ldb_batch_t *batch);

void
btc_account_sync(btc_account_t *acct,
                 ldb_batch_t *batch,
                 uint32_t receive,
                 uint32_t change);

void
btc_account_next(btc_account_t *acct, ldb_batch_t *batch);

void
btc_account_prev(btc_account_t *acct, ldb_batch_t *batch);

void
btc_account_generate(btc_account_t *acct,
                     ldb_batch_t *batch,
                     const char *name,
                     const btc_master_t *master,
                     uint32_t index);

void
btc_account_watch(btc_account_t *acct,
                  ldb_batch_t *batch,
                  const char *name,
                  const btc_hdnode_t *node,
                  uint32_t index);

#endif /* BTC_WALLET_ACCOUNT_H_ */
