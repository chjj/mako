/*!
 * database.h - wallet database for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifndef BTC_WALLET_DATABASE_H_
#define BTC_WALLET_DATABASE_H_

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <lcdb.h>

#include <mako/address.h>
#include <mako/coins.h>
#include <mako/tx.h>
#include <mako/util.h>

#include "../bio.h"
#include "../impl.h"

#include "account.h"
#include "master.h"
#include "record.h"
#include "wallet.h"

/**
 * Database Keys
 *
 * Layout:
 *
 *   F -> flags
 *   W -> wallet
 *   K -> master key
 *   S -> sync state
 *
 *   a[acct] -> account
 *   b[acct] -> account balance
 *   i[name] -> account index
 *
 *   r[addr] -> address path
 *   e[height] -> recent block hash
 *
 *   c[hash][index] -> coin
 *   u[hash][index] -> undo coin
 *   s[hash][index] -> spender
 *
 *   t[hash] -> tx data
 *   k[hash] -> tx meta
 *
 *   q[height] -> block meta
 *   Q[height][idx] -> txid
 *
 *   m[id] -> txid
 *   h[height][id] -> txid (tx by height)
 *
 *   R[acct][addr] -> dummy (path by account)
 *   C[acct][hash][index] -> dummy (coin by account)
 *
 *   M[acct][id] -> txid
 *   H[acct][height][id] -> txid (tx by account/height)
 */

#define KEY_INT32_MIN 0x00, 0x00, 0x00, 0x00
#define KEY_INT32_MAX 0xff, 0xff, 0xff, 0xff

#define KEY_INT64_MIN 0x00, 0x00, 0x00, 0x00, \
                      0x00, 0x00, 0x00, 0x00

#define KEY_INT64_MAX 0xff, 0xff, 0xff, 0xff, \
                      0xff, 0xff, 0xff, 0xff

#define KEY_HASH256_MIN                           \
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00

#define KEY_HASH256_MAX                           \
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, \
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, \
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, \
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff

#define KEY_HASH320_MIN KEY_HASH256_MIN, KEY_INT64_MIN
#define KEY_HASH320_MAX KEY_HASH256_MAX, KEY_INT64_MAX

#define KEY_MAX_LEN KEY_INDEX_LEN

/*
 * Helper Keys
 */

static uint8_t key_dummy_[1] = {0};
static const ldb_slice_t key_dummy = {key_dummy_, 1, 0};

/*
 * Root Keys
 */

static uint8_t key_flags_[1] = {'F'};
static uint8_t key_wallet_[1] = {'W'};
static uint8_t key_master_[1] = {'K'};
static uint8_t key_state_[1] = {'S'};

static const ldb_slice_t key_flags = {key_flags_, 1, 0};
static const ldb_slice_t key_wallet = {key_wallet_, 1, 0};
static const ldb_slice_t key_master = {key_master_, 1, 0};
static const ldb_slice_t key_state = {key_state_, 1, 0};

/*
 * Account Key (a[acct])
 */

#define KEY_ACCOUNT_CH 'a'
#define KEY_ACCOUNT_LEN 5

static ldb_slice_t
key_account(uint32_t account, uint8_t *buf) {
  buf[0] = KEY_ACCOUNT_CH;
  btc_write32be(buf + 1, account);
  return ldb_slice(buf, KEY_ACCOUNT_LEN);
}

/*
 * Account Balance Key (b[acct])
 */

#define KEY_BALANCE_CH 'b'
#define KEY_BALANCE_LEN 5

static ldb_slice_t
key_balance(uint32_t account, uint8_t *buf) {
  buf[0] = KEY_BALANCE_CH;
  btc_write32be(buf + 1, account);
  return ldb_slice(buf, KEY_BALANCE_LEN);
}

/*
 * Account Index Key (i[name])
 */

#define KEY_INDEX_CH 'i'
#define KEY_INDEX_LEN 64

static ldb_slice_t
key_index(const char *name, uint8_t *buf) {
  size_t len = strlen(name);

  if (len > 63)
    len = 63;

  buf[0] = KEY_INDEX_CH;

  memcpy(buf + 1, name, len);

  return ldb_slice(buf, 1 + len);
}

/*
 * Path Key (r[addr])
 */

#define KEY_PATH_CH 'r'
#define KEY_PATH_LEN 42

static uint8_t key_path_min_[4] = {KEY_PATH_CH, 0x00, 0x00, 0x00};
static uint8_t key_path_max_[42] = {KEY_PATH_CH, 0xff, KEY_HASH320_MAX};

BTC_UNUSED static const ldb_slice_t key_path_min = {key_path_min_, 4, 0};
BTC_UNUSED static const ldb_slice_t key_path_max = {key_path_max_, 42, 0};

static ldb_slice_t
key_path(const btc_address_t *addr, uint8_t *buf) {
  buf[0] = KEY_PATH_CH;
  buf[1] = (addr->type << 5) | addr->version;
  memcpy(buf + 2, addr->hash, addr->length);
  return ldb_slice(buf, 2 + addr->length);
}

/*
 * Block Hash Key (e[height])
 */

#define KEY_BLOCK_CH 'e'
#define KEY_BLOCK_LEN 5

static ldb_slice_t
key_block(int32_t height, uint8_t *buf) {
  buf[0] = KEY_BLOCK_CH;
  btc_write32be(buf + 1, height);
  return ldb_slice(buf, KEY_BLOCK_LEN);
}

/*
 * Coin Key (c[hash][index])
 */

#define KEY_COIN_CH 'c'
#define KEY_COIN_LEN 37

static uint8_t key_coin_min_[KEY_COIN_LEN] = {KEY_COIN_CH, KEY_HASH256_MIN,
                                                           KEY_INT32_MIN};
static uint8_t key_coin_max_[KEY_COIN_LEN] = {KEY_COIN_CH, KEY_HASH256_MAX,
                                                           KEY_INT32_MAX};

BTC_UNUSED static const ldb_slice_t key_coin_min = {key_coin_min_,
                                                    KEY_COIN_LEN, 0};
BTC_UNUSED static const ldb_slice_t key_coin_max = {key_coin_max_,
                                                    KEY_COIN_LEN, 0};

static ldb_slice_t
key_coin(const uint8_t *hash, uint32_t index, uint8_t *buf) {
  buf[0] = KEY_COIN_CH;
  memcpy(buf + 1, hash, 32);
  btc_write32be(buf + 33, index);
  return ldb_slice(buf, KEY_COIN_LEN);
}

/*
 * Undo Key (u[hash][index])
 */

#define KEY_UNDO_CH 'u'
#define KEY_UNDO_LEN 37

static ldb_slice_t
key_undo(const uint8_t *hash, uint32_t index, uint8_t *buf) {
  buf[0] = KEY_UNDO_CH;
  memcpy(buf + 1, hash, 32);
  btc_write32be(buf + 33, index);
  return ldb_slice(buf, KEY_UNDO_LEN);
}

/*
 * Spender Key (s[hash][index])
 */

#define KEY_SPEND_CH 's'
#define KEY_SPEND_LEN 37

static ldb_slice_t
key_spend(const uint8_t *hash, uint32_t index, uint8_t *buf) {
  buf[0] = KEY_SPEND_CH;
  memcpy(buf + 1, hash, 32);
  btc_write32be(buf + 33, index);
  return ldb_slice(buf, KEY_SPEND_LEN);
}

/*
 * Transaction Key (t[hash])
 */

#define KEY_TX_CH 't'
#define KEY_TX_LEN 33

static ldb_slice_t
key_tx(const uint8_t *hash, uint8_t *buf) {
  buf[0] = KEY_TX_CH;
  memcpy(buf + 1, hash, 32);
  return ldb_slice(buf, KEY_TX_LEN);
}

/*
 * Transaction Meta Key (k[hash])
 */

#define KEY_TXMETA_CH 'k'
#define KEY_TXMETA_LEN 33

static ldb_slice_t
key_txmeta(const uint8_t *hash, uint8_t *buf) {
  buf[0] = KEY_TXMETA_CH;
  memcpy(buf + 1, hash, 32);
  return ldb_slice(buf, KEY_TXMETA_LEN);
}

/*
 * Block Meta Key (q[height])
 */

#define KEY_BLKMETA_CH 'q'
#define KEY_BLKMETA_LEN 5

static ldb_slice_t
key_blkmeta(int32_t height, uint8_t *buf) {
  buf[0] = KEY_BLKMETA_CH;
  btc_write32be(buf + 1, height);
  return ldb_slice(buf, KEY_BLKMETA_LEN);
}

/*
 * Block Index Key (Q[height][idx])
 */

#define KEY_BLKIDX_CH 'Q'
#define KEY_BLKIDX_LEN 9

static ldb_slice_t
key_blkidx(int32_t height, int32_t index, uint8_t *buf) {
  buf[0] = KEY_BLKIDX_CH;
  btc_write32be(buf + 1, height);
  btc_write32be(buf + 5, index);
  return ldb_slice(buf, KEY_BLKIDX_LEN);
}

/*
 * TXID Key (m[id])
 */

#define KEY_TXID_CH 'm'
#define KEY_TXID_LEN 9

static ldb_slice_t
key_txid(uint64_t id, uint8_t *buf) {
  buf[0] = KEY_TXID_CH;
  btc_write64be(buf + 1, id);
  return ldb_slice(buf, KEY_TXID_LEN);
}

/*
 * Height Key (h[height][id])
 */

#define KEY_HEIGHT_CH 'h'
#define KEY_HEIGHT_LEN 13

static ldb_slice_t
key_height(int32_t height, uint64_t id, uint8_t *buf) {
  buf[0] = KEY_HEIGHT_CH;
  btc_write32be(buf + 1, height);
  btc_write64be(buf + 5, id);
  return ldb_slice(buf, KEY_HEIGHT_LEN);
}

/*
 * Account Path Key (R[acct][addr])
 */

#define KEY_APATH_CH 'R'
#define KEY_APATH_LEN 46

static ldb_slice_t
key_apath(uint32_t account, const btc_address_t *addr, uint8_t *buf) {
  buf[0] = KEY_APATH_CH;
  btc_write32be(buf + 1, account);
  buf[5] = (addr->type << 5) | addr->version;
  memcpy(buf + 6, addr->hash, addr->length);
  return ldb_slice(buf, 6 + addr->length);
}

/*
 * Account Coin Key (C[acct][hash][index])
 */

#define KEY_ACOIN_CH 'C'
#define KEY_ACOIN_LEN 41

static ldb_slice_t
key_acoin(uint32_t account, const uint8_t *hash, uint32_t index, uint8_t *buf) {
  buf[0] = KEY_ACOIN_CH;
  btc_write32be(buf + 1, account);
  memcpy(buf + 5, hash, 32);
  btc_write32be(buf + 37, index);
  return ldb_slice(buf, KEY_ACOIN_LEN);
}

/*
 * Account Time Key (M[acct][id])
 */

#define KEY_ATXID_CH 'M'
#define KEY_ATXID_LEN 13

static ldb_slice_t
key_atxid(uint32_t account, uint64_t id, uint8_t *buf) {
  buf[0] = KEY_ATXID_CH;
  btc_write32be(buf + 1, account);
  btc_write64be(buf + 5, id);
  return ldb_slice(buf, KEY_ATXID_LEN);
}

/*
 * Account Height Key (H[acct][height][id])
 */

#define KEY_AHEIGHT_CH 'H'
#define KEY_AHEIGHT_LEN 17

static ldb_slice_t
key_aheight(uint32_t account, int32_t height, uint64_t id, uint8_t *buf) {
  buf[0] = KEY_AHEIGHT_CH;
  btc_write32be(buf + 1, account);
  btc_write32be(buf + 5, height);
  btc_write64be(buf + 9, id);
  return ldb_slice(buf, KEY_AHEIGHT_LEN);
}

/*
 * DB Helpers
 */

static int
db_abort(char *name, int code) {
  fprintf(stderr, "%s: %s\n", name, ldb_strerror(code));
  fflush(stderr);
  abort();
  return 0;
}

/*
 * Write Helpers
 */

BTC_UNUSED static void
db_batch(ldb_batch_t *batch) {
  ldb_batch_init(batch);
}

BTC_UNUSED static void
db_clear(ldb_batch_t *batch) {
  ldb_batch_clear(batch);
}

BTC_UNUSED static void
db_write(ldb_t *db, ldb_batch_t *batch) {
  int rc = ldb_write(db, batch, 0);

  ldb_batch_clear(batch);

  if (rc != LDB_OK)
    db_abort("db_write", rc);
}

BTC_UNUSED static void
db_put_flags(ldb_batch_t *batch, uint32_t magic, uint32_t flags) {
  ldb_slice_t val;
  uint8_t zp[8];

  btc_uint32_write(zp + 0, magic);
  btc_uint32_write(zp + 4, flags);

  val.data = zp;
  val.size = sizeof(zp);

  ldb_batch_put(batch, &key_flags, &val);
}

BTC_UNUSED static void
db_put_wallet(ldb_batch_t *batch, const btc_wallet_t *wallet) {
  ldb_slice_t val;
  uint8_t zp[80];

  val.data = zp;
  val.size = btc_wallet_export(zp, wallet);

  ldb_batch_put(batch, &key_wallet, &val);
}

BTC_UNUSED static void
db_put_master(ldb_batch_t *batch, const btc_master_t *master) {
  uint8_t zp[237];
  ldb_slice_t val;

  val.data = zp;
  val.size = btc_master_export(zp, master);

  ldb_batch_put(batch, &key_master, &val);

  btc_memzero(zp, sizeof(zp));
}

BTC_UNUSED static void
db_put_state(ldb_batch_t *batch, const btc_state_t *state) {
  ldb_slice_t val;
  uint8_t zp[41];

  val.data = zp;
  val.size = btc_state_export(zp, state);

  ldb_batch_put(batch, &key_state, &val);
}

BTC_UNUSED static void
db_put_account(ldb_batch_t *batch,
               uint32_t account,
               const btc_account_t *acct) {
  uint8_t buf[KEY_ACCOUNT_LEN];
  ldb_slice_t key, val;
  uint8_t zp[156];

  key = key_account(account, buf);

  val.data = zp;
  val.size = btc_account_export(zp, acct);

  ldb_batch_put(batch, &key, &val);
}

BTC_UNUSED static void
db_del_account(ldb_batch_t *batch, uint32_t account) {
  uint8_t buf[KEY_ACCOUNT_LEN];
  ldb_slice_t key;

  key = key_account(account, buf);

  ldb_batch_del(batch, &key);
}

BTC_UNUSED static void
db_put_balance(ldb_batch_t *batch, uint32_t account, const btc_balance_t *bal) {
  uint8_t buf[KEY_BALANCE_LEN];
  ldb_slice_t key, val;
  uint8_t zp[32];

  key = key_balance(account, buf);

  val.data = zp;
  val.size = btc_balance_export(zp, bal);

  ldb_batch_put(batch, &key, &val);
}

BTC_UNUSED static void
db_del_balance(ldb_batch_t *batch, uint32_t account) {
  uint8_t buf[KEY_BALANCE_LEN];
  ldb_slice_t key;

  key = key_balance(account, buf);

  ldb_batch_del(batch, &key);
}

BTC_UNUSED static void
db_put_index(ldb_batch_t *batch, const char *name, uint32_t account) {
  uint8_t buf[KEY_INDEX_LEN];
  ldb_slice_t key, val;
  uint8_t zp[4];

  key = key_index(name, buf);

  btc_uint32_write(zp, account);

  val.data = zp;
  val.size = sizeof(zp);

  ldb_batch_put(batch, &key, &val);
}

BTC_UNUSED static void
db_del_index(ldb_batch_t *batch, const char *name) {
  uint8_t buf[KEY_INDEX_LEN];
  ldb_slice_t key;

  key = key_index(name, buf);

  ldb_batch_del(batch, &key);
}

BTC_UNUSED static void
db_put_path(ldb_batch_t *batch,
            const btc_address_t *addr,
            const btc_path_t *path) {
  uint8_t buf[KEY_PATH_LEN];
  ldb_slice_t key, val;
  uint8_t zp[12];

  key = key_path(addr, buf);

  val.data = zp;
  val.size = btc_path_export(zp, path);

  ldb_batch_put(batch, &key, &val);
}

BTC_UNUSED static void
db_del_path(ldb_batch_t *batch, const btc_address_t *addr) {
  uint8_t buf[KEY_PATH_LEN];
  ldb_slice_t key;

  key = key_path(addr, buf);

  ldb_batch_del(batch, &key);
}

BTC_UNUSED static void
db_put_block(ldb_batch_t *batch, int32_t height, const uint8_t *hash) {
  uint8_t buf[KEY_BLOCK_LEN];
  ldb_slice_t key, val;

  key = key_block(height, buf);

  val.data = (void *)hash;
  val.size = 32;

  ldb_batch_put(batch, &key, &val);
}

BTC_UNUSED static void
db_del_block(ldb_batch_t *batch, int32_t height) {
  uint8_t buf[KEY_BLOCK_LEN];
  ldb_slice_t key;

  key = key_block(height, buf);

  ldb_batch_del(batch, &key);
}

BTC_UNUSED static void
db_put_coin(ldb_batch_t *batch,
            const uint8_t *hash,
            uint32_t index,
            const btc_coin_t *coin) {
  uint8_t buf[KEY_COIN_LEN];
  ldb_slice_t key, val;
  uint8_t *zp;
  size_t zn;

  key = key_coin(hash, index, buf);

  btc_credit_encode(&zp, &zn, coin);

  val.data = zp;
  val.size = zn;

  ldb_batch_put(batch, &key, &val);

  btc_free(zp);
}

BTC_UNUSED static void
db_del_coin(ldb_batch_t *batch, const uint8_t *hash, uint32_t index) {
  uint8_t buf[KEY_COIN_LEN];
  ldb_slice_t key;

  key = key_coin(hash, index, buf);

  ldb_batch_del(batch, &key);
}

BTC_UNUSED static void
db_put_undo(ldb_batch_t *batch,
            const uint8_t *hash,
            uint32_t index,
            const btc_coin_t *coin) {
  uint8_t buf[KEY_UNDO_LEN];
  ldb_slice_t key, val;
  uint8_t *zp;
  size_t zn;

  key = key_undo(hash, index, buf);

  btc_coin_encode(&zp, &zn, coin);

  val.data = zp;
  val.size = zn;

  ldb_batch_put(batch, &key, &val);

  btc_free(zp);
}

BTC_UNUSED static void
db_del_undo(ldb_batch_t *batch, const uint8_t *hash, uint32_t index) {
  uint8_t buf[KEY_UNDO_LEN];
  ldb_slice_t key;

  key = key_undo(hash, index, buf);

  ldb_batch_del(batch, &key);
}

BTC_UNUSED static void
db_put_spend(ldb_batch_t *batch,
             const uint8_t *hash,
             uint32_t index,
             const btc_outpoint_t *spender) {
  uint8_t buf[KEY_SPEND_LEN];
  ldb_slice_t key, val;
  uint8_t raw[36];

  key = key_spend(hash, index, buf);

  btc_outpoint_write(raw, spender);

  val.data = raw;
  val.size = 36;

  ldb_batch_put(batch, &key, &val);
}

BTC_UNUSED static void
db_del_spend(ldb_batch_t *batch, const uint8_t *hash, uint32_t index) {
  uint8_t buf[KEY_SPEND_LEN];
  ldb_slice_t key;

  key = key_spend(hash, index, buf);

  ldb_batch_del(batch, &key);
}

BTC_UNUSED static void
db_put_tx(ldb_batch_t *batch, const uint8_t *hash, const btc_tx_t *tx) {
  uint8_t buf[KEY_TX_LEN];
  ldb_slice_t key, val;
  uint8_t *zp;
  size_t zn;

  key = key_tx(hash, buf);

  btc_tx_encode(&zp, &zn, tx);

  val.data = zp;
  val.size = zn;

  ldb_batch_put(batch, &key, &val);

  btc_free(zp);
}

BTC_UNUSED static void
db_del_tx(ldb_batch_t *batch, const uint8_t *hash) {
  uint8_t buf[KEY_TX_LEN];
  ldb_slice_t key;

  key = key_tx(hash, buf);

  ldb_batch_del(batch, &key);
}

BTC_UNUSED static void
db_put_txmeta(ldb_batch_t *batch,
              const uint8_t *hash,
              const btc_txmeta_t *meta) {
  uint8_t buf[KEY_TXMETA_LEN];
  ldb_slice_t key, val;
  uint8_t zp[76];

  key = key_txmeta(hash, buf);

  btc_txmeta_write(zp, meta);

  val.data = zp;
  val.size = sizeof(zp);

  ldb_batch_put(batch, &key, &val);
}

BTC_UNUSED static void
db_del_txmeta(ldb_batch_t *batch, const uint8_t *hash) {
  uint8_t buf[KEY_TXMETA_LEN];
  ldb_slice_t key;

  key = key_txmeta(hash, buf);

  ldb_batch_del(batch, &key);
}

BTC_UNUSED static void
db_put_blkmeta(ldb_batch_t *batch,
               int32_t height,
               const uint8_t *hash,
               int64_t time) {
  uint8_t buf[KEY_BLKMETA_LEN];
  ldb_slice_t key, val;
  uint8_t zp[40];

  key = key_blkmeta(height, buf);

  btc_raw_write(zp + 0, hash, 32);
  btc_int64_write(zp + 32, time);

  val.data = zp;
  val.size = sizeof(zp);

  ldb_batch_put(batch, &key, &val);
}

BTC_UNUSED static void
db_del_blkmeta(ldb_batch_t *batch, int32_t height) {
  uint8_t buf[KEY_BLKMETA_LEN];
  ldb_slice_t key;

  key = key_blkmeta(height, buf);

  ldb_batch_del(batch, &key);
}

BTC_UNUSED static void
db_put_blkidx(ldb_batch_t *batch,
              int32_t height,
              int32_t index,
              const uint8_t *hash) {
  uint8_t buf[KEY_BLKIDX_LEN];
  ldb_slice_t key, val;

  key = key_blkidx(height, index, buf);

  val.data = (void *)hash;
  val.size = 32;

  ldb_batch_put(batch, &key, &val);
}

BTC_UNUSED static void
db_del_blkidx(ldb_batch_t *batch, int32_t height, int32_t index) {
  uint8_t buf[KEY_BLKIDX_LEN];
  ldb_slice_t key;

  key = key_blkidx(height, index, buf);

  ldb_batch_del(batch, &key);
}

BTC_UNUSED static void
db_put_txid(ldb_batch_t *batch, uint64_t id, const uint8_t *hash) {
  uint8_t buf[KEY_TXID_LEN];
  ldb_slice_t key, val;

  key = key_txid(id, buf);

  val.data = (void *)hash;
  val.size = 32;

  ldb_batch_put(batch, &key, &val);
}

BTC_UNUSED static void
db_del_txid(ldb_batch_t *batch, uint64_t id) {
  uint8_t buf[KEY_TXID_LEN];
  ldb_slice_t key;

  key = key_txid(id, buf);

  ldb_batch_del(batch, &key);
}

BTC_UNUSED static void
db_put_height(ldb_batch_t *batch,
              int32_t height,
              uint64_t id,
              const uint8_t *hash) {
  uint8_t buf[KEY_HEIGHT_LEN];
  ldb_slice_t key, val;

  key = key_height(height, id, buf);

  val.data = (void *)hash;
  val.size = 32;

  ldb_batch_put(batch, &key, &val);
}

BTC_UNUSED static void
db_del_height(ldb_batch_t *batch, int32_t height, uint64_t id) {
  uint8_t buf[KEY_HEIGHT_LEN];
  ldb_slice_t key;

  key = key_height(height, id, buf);

  ldb_batch_del(batch, &key);
}

BTC_UNUSED static void
db_put_apath(ldb_batch_t *batch, uint32_t account, const btc_address_t *addr) {
  uint8_t buf[KEY_APATH_LEN];
  ldb_slice_t key;

  key = key_apath(account, addr, buf);

  ldb_batch_put(batch, &key, &key_dummy);
}

BTC_UNUSED static void
db_del_apath(ldb_batch_t *batch, uint32_t account, const btc_address_t *addr) {
  uint8_t buf[KEY_APATH_LEN];
  ldb_slice_t key;

  key = key_apath(account, addr, buf);

  ldb_batch_del(batch, &key);
}

BTC_UNUSED static void
db_put_acoin(ldb_batch_t *batch,
             uint32_t account,
             const uint8_t *hash,
             uint32_t index) {
  uint8_t buf[KEY_ACOIN_LEN];
  ldb_slice_t key;

  key = key_acoin(account, hash, index, buf);

  ldb_batch_put(batch, &key, &key_dummy);
}

BTC_UNUSED static void
db_del_acoin(ldb_batch_t *batch,
             uint32_t account,
             const uint8_t *hash,
             uint32_t index) {
  uint8_t buf[KEY_ACOIN_LEN];
  ldb_slice_t key;

  key = key_acoin(account, hash, index, buf);

  ldb_batch_del(batch, &key);
}

BTC_UNUSED static void
db_put_atxid(ldb_batch_t *batch,
             uint32_t account,
             uint64_t id,
             const uint8_t *hash) {
  uint8_t buf[KEY_ATXID_LEN];
  ldb_slice_t key, val;

  key = key_atxid(account, id, buf);

  val.data = (void *)hash;
  val.size = 32;

  ldb_batch_put(batch, &key, &val);
}

BTC_UNUSED static void
db_del_atxid(ldb_batch_t *batch, uint32_t account, uint64_t id) {
  uint8_t buf[KEY_ATXID_LEN];
  ldb_slice_t key;

  key = key_atxid(account, id, buf);

  ldb_batch_del(batch, &key);
}

BTC_UNUSED static void
db_put_aheight(ldb_batch_t *batch,
               uint32_t account,
               int32_t height,
               uint64_t id,
               const uint8_t *hash) {
  uint8_t buf[KEY_AHEIGHT_LEN];
  ldb_slice_t key, val;

  key = key_aheight(account, height, id, buf);

  val.data = (void *)hash;
  val.size = 32;

  ldb_batch_put(batch, &key, &val);
}

BTC_UNUSED static void
db_del_aheight(ldb_batch_t *batch,
               uint32_t account,
               int32_t height,
               uint64_t id) {
  uint8_t buf[KEY_AHEIGHT_LEN];
  ldb_slice_t key;

  key = key_aheight(account, height, id, buf);

  ldb_batch_del(batch, &key);
}

/*
 * Read Helpers
 */

BTC_UNUSED static int
db_get(ldb_t *db, const ldb_slice_t *key, ldb_slice_t *val) {
  int rc = ldb_get(db, key, val, 0);

  if (rc == LDB_OK)
    return 1;

  if (rc == LDB_NOTFOUND)
    return 0;

  return db_abort("db_get", rc);
}

BTC_UNUSED static int
db_has(ldb_t *db, const ldb_slice_t *key) {
  int rc = ldb_has(db, key, 0);

  if (rc == LDB_OK)
    return 1;

  if (rc == LDB_NOTFOUND)
    return 0;

  return db_abort("db_has", rc);
}

BTC_UNUSED static int
db_get_size(ldb_t *db, const ldb_slice_t *key, ldb_slice_t *val, size_t size) {
  if (!db_get(db, key, val))
    return 0;

  if (val->size == size)
    return 1;

  ldb_free(val->data);

  return db_abort("db_get_size", LDB_CORRUPTION);
}

BTC_UNUSED static int
db_get_flags(ldb_t *db, uint32_t *magic, uint32_t *flags) {
  ldb_slice_t val;

  if (!db_get_size(db, &key_flags, &val, 8))
    return 0;

  *magic = btc_read32le((uint8_t *)val.data + 0);
  *flags = btc_read32le((uint8_t *)val.data + 4);

  ldb_free(val.data);

  return 1;
}

BTC_UNUSED static int
db_get_wallet(ldb_t *db, btc_wallet_t *wallet) {
  ldb_slice_t val;

  if (!db_get(db, &key_wallet, &val))
    return 0;

  if (!btc_wallet_import(wallet, val.data, val.size))
    return db_abort("db_get_wallet", LDB_CORRUPTION);

  ldb_free(val.data);

  return 1;
}

BTC_UNUSED static int
db_get_master(ldb_t *db, btc_master_t *master) {
  ldb_slice_t val;

  if (!db_get(db, &key_master, &val))
    return 0;

  if (!btc_master_import(master, val.data, val.size))
    return db_abort("db_get_master", LDB_CORRUPTION);

  btc_memzero(val.data, val.size);

  ldb_free(val.data);

  return 1;
}

BTC_UNUSED static int
db_get_state(ldb_t *db, btc_state_t *state) {
  ldb_slice_t val;

  if (!db_get(db, &key_state, &val))
    return 0;

  if (!btc_state_import(state, val.data, val.size))
    return db_abort("db_get_state", LDB_CORRUPTION);

  ldb_free(val.data);

  return 1;
}

BTC_UNUSED static int
db_get_account(ldb_t *db, uint32_t account, btc_account_t *acct) {
  uint8_t buf[KEY_ACCOUNT_LEN];
  ldb_slice_t key, val;

  key = key_account(account, buf);

  if (!db_get(db, &key, &val))
    return 0;

  if (!btc_account_import(acct, val.data, val.size))
    return db_abort("db_get_account", LDB_CORRUPTION);

  ldb_free(val.data);

  return 1;
}

BTC_UNUSED static int
db_has_account(ldb_t *db, uint32_t account) {
  uint8_t buf[KEY_ACCOUNT_LEN];
  ldb_slice_t key;

  key = key_account(account, buf);

  return db_has(db, &key);
}

BTC_UNUSED static int
db_get_balance(ldb_t *db, uint32_t account, btc_balance_t *bal) {
  uint8_t buf[KEY_BALANCE_LEN];
  ldb_slice_t key, val;

  key = key_balance(account, buf);

  if (!db_get(db, &key, &val))
    return 0;

  if (!btc_balance_import(bal, val.data, val.size))
    return db_abort("db_get_balance", LDB_CORRUPTION);

  ldb_free(val.data);

  return 1;
}

BTC_UNUSED static void
db_update_balance(ldb_t *db,
                  ldb_batch_t *batch,
                  uint32_t account,
                  const btc_balance_t *delta) {
  btc_balance_t bal;

  if (!db_get_balance(db, account, &bal))
    btc_balance_init(&bal);

  btc_balance_apply(&bal, delta);

  db_put_balance(batch, account, &bal);
}

BTC_UNUSED static int
db_get_name(ldb_t *db, uint32_t account, char *name, size_t size) {
  uint8_t buf[KEY_ACCOUNT_LEN];
  ldb_slice_t key, val;

  key = key_account(account, buf);

  if (!db_get(db, &key, &val))
    return 0;

  if (!btc_account_import_name(name, size, val.data, val.size))
    return db_abort("db_get_name", LDB_CORRUPTION);

  ldb_free(val.data);

  return 1;
}

BTC_UNUSED static int
db_get_index(ldb_t *db, const char *name, uint32_t *account) {
  uint8_t buf[KEY_INDEX_LEN];
  ldb_slice_t key, val;

  key = key_index(name, buf);

  if (!db_get_size(db, &key, &val, 4))
    return 0;

  *account = btc_read32le(val.data);

  ldb_free(val.data);

  return 1;
}

BTC_UNUSED static int
db_has_index(ldb_t *db, const char *name) {
  uint8_t buf[KEY_INDEX_LEN];
  ldb_slice_t key;

  key = key_index(name, buf);

  return db_has(db, &key);
}

BTC_UNUSED static int
db_get_path(ldb_t *db, const btc_address_t *addr, btc_path_t *path) {
  uint8_t buf[KEY_PATH_LEN];
  ldb_slice_t key, val;

  key = key_path(addr, buf);

  if (!db_get(db, &key, &val))
    return 0;

  if (!btc_path_import(path, val.data, val.size))
    return db_abort("db_get_path", LDB_CORRUPTION);

  ldb_free(val.data);

  return 1;
}

BTC_UNUSED static int
db_get_block(ldb_t *db, int32_t height, uint8_t *hash) {
  uint8_t buf[KEY_BLOCK_LEN];
  ldb_slice_t key, val;

  key = key_block(height, buf);

  if (!db_get_size(db, &key, &val, 32))
    return 0;

  memcpy(hash, val.data, 32);

  ldb_free(val.data);

  return 1;
}

BTC_UNUSED static int
db_get_coin(ldb_t *db, const uint8_t *hash, uint32_t index, btc_coin_t **coin) {
  uint8_t buf[KEY_COIN_LEN];
  ldb_slice_t key, val;

  key = key_coin(hash, index, buf);

  if (!db_get(db, &key, &val))
    return 0;

  *coin = btc_credit_decode(val.data, val.size);

  if (*coin == NULL)
    return db_abort("db_get_coin", LDB_CORRUPTION);

  ldb_free(val.data);

  return 1;
}

BTC_UNUSED static int
db_get_undo(ldb_t *db, const uint8_t *hash, uint32_t index, btc_coin_t **coin) {
  uint8_t buf[KEY_UNDO_LEN];
  ldb_slice_t key, val;

  key = key_undo(hash, index, buf);

  if (!db_get(db, &key, &val))
    return 0;

  *coin = btc_coin_decode(val.data, val.size);

  if (*coin == NULL)
    return db_abort("db_get_undo", LDB_CORRUPTION);

  ldb_free(val.data);

  return 1;
}

BTC_UNUSED static int
db_get_spend(ldb_t *db,
             const uint8_t *hash,
             uint32_t index,
             btc_outpoint_t *spender) {
  uint8_t buf[KEY_SPEND_LEN];
  ldb_slice_t key, val;

  key = key_spend(hash, index, buf);

  if (!db_get_size(db, &key, &val, 36))
    return 0;

  btc_outpoint_import(spender, val.data, 36);

  ldb_free(val.data);

  return 1;
}

BTC_UNUSED static void
db_update_undo(ldb_t *db,
               ldb_batch_t *batch,
               const uint8_t *hash,
               uint32_t index,
               int32_t height) {
  btc_outpoint_t spend;
  btc_coin_t *undo;

  if (!db_get_spend(db, hash, index, &spend))
    return;

  if (!db_get_undo(db, spend.hash, spend.index, &undo))
    return;

  undo->height = height;

  db_put_undo(batch, spend.hash, spend.index, undo);

  btc_coin_destroy(undo);
}

BTC_UNUSED static int
db_get_tx(ldb_t *db, const uint8_t *hash, btc_tx_t **tx) {
  uint8_t buf[KEY_TX_LEN];
  ldb_slice_t key, val;

  key = key_tx(hash, buf);

  if (!db_get(db, &key, &val))
    return 0;

  *tx = btc_tx_decode(val.data, val.size);

  if (*tx == NULL)
    return db_abort("db_get_tx", LDB_CORRUPTION);

  ldb_free(val.data);

  return 1;
}

BTC_UNUSED static int
db_get_txmeta(ldb_t *db, const uint8_t *hash, btc_txmeta_t *meta) {
  uint8_t buf[KEY_TXMETA_LEN];
  ldb_slice_t key, val;

  key = key_txmeta(hash, buf);

  if (!db_get(db, &key, &val))
    return 0;

  if (!btc_txmeta_import(meta, val.data, val.size))
    return db_abort("get_txmeta", LDB_CORRUPTION);

  ldb_free(val.data);

  return 1;
}

BTC_UNUSED static int
db_get_blkmeta(ldb_t *db, int32_t height, uint8_t *hash, int64_t *time) {
  uint8_t buf[KEY_BLKMETA_LEN];
  ldb_slice_t key, val;

  key = key_blkmeta(height, buf);

  if (!db_get_size(db, &key, &val, 64))
    return 0;

  memcpy(hash, val.data, 32);

  *time = btc_read64le((uint8_t *)val.data + 32);

  ldb_free(val.data);

  return 1;
}

BTC_UNUSED static int
db_get_blkidx(ldb_t *db, int32_t height, int32_t index, uint8_t *hash) {
  uint8_t buf[KEY_BLKIDX_LEN];
  ldb_slice_t key, val;

  key = key_blkidx(height, index, buf);

  if (!db_get_size(db, &key, &val, 32))
    return 0;

  memcpy(hash, val.data, 32);

  ldb_free(val.data);

  return 1;
}

BTC_UNUSED static int
db_get_txid(ldb_t *db, uint64_t id, uint8_t *hash) {
  uint8_t buf[KEY_TXID_LEN];
  ldb_slice_t key, val;

  key = key_txid(id, buf);

  if (!db_get_size(db, &key, &val, 32))
    return 0;

  memcpy(hash, val.data, 32);

  ldb_free(val.data);

  return 1;
}

#endif /* BTC_WALLET_DATABASE_H_ */
