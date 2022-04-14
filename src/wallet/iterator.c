/*!
 * iterator.c - wallet iterators for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <mako/coins.h>
#include <mako/tx.h>
#include <mako/util.h>

#include "../bio.h"
#include "../impl.h"
#include "../internal.h"

#include "database.h"
#include "iterator.h"
#include "record.h"

/*
 * Account Iterator
 */

struct btc_acctiter_s {
  ldb_t *db;
  ldb_iter_t *it;
  uint32_t account;
  btc_balance_t balance;
  uint8_t min_buf[KEY_INDEX_LEN];
  uint8_t max_buf[KEY_INDEX_LEN];
  ldb_slice_t min, max;
  char name[64];
  int valid;
};

btc_acctiter_t *
btc_acctiter_create(ldb_t *db) {
  btc_acctiter_t *iter = btc_malloc(sizeof(btc_acctiter_t));

  memset(iter, 0, sizeof(*iter));

  iter->db = db;
  iter->it = ldb_iterator(db, 0);
  iter->min.data = iter->min_buf;
  iter->max.data = iter->max_buf;

  return iter;
}

void
btc_acctiter_destroy(btc_acctiter_t *iter) {
  int rc = ldb_iter_status(iter->it);

  if (rc != LDB_OK)
    db_abort("acctiter_destroy", rc);

  ldb_iter_destroy(iter->it);

  btc_free(iter);
}

static void
btc_acctiter_parse_key(btc_acctiter_t *iter) {
  ldb_slice_t key = ldb_iter_key(iter->it);
  ldb_slice_t val = ldb_iter_val(iter->it);

  if (key.size == 0 || key.size > 64 || val.size != 4)
    db_abort("acctiter_parse_key", LDB_CORRUPTION);

  memcpy(iter->name, (char *)key.data + 1, key.size - 1);

  iter->name[key.size - 1] = '\0';
  iter->account = btc_read32le(val.data);
}

static void
btc_acctiter_update(btc_acctiter_t *iter) {
  iter->valid = ldb_iter_valid(iter->it);

  if (iter->valid) {
    iter->valid = ldb_iter_compare(iter->it, &iter->max) <= 0;

    if (iter->valid)
      btc_acctiter_parse_key(iter);
  }
}

int
btc_acctiter_valid(btc_acctiter_t *iter) {
  return iter->valid;
}

static void
btc_acctiter_preseek(btc_acctiter_t *iter, const char *name) {
  uint8_t *min = iter->min_buf;
  uint8_t *max = iter->max_buf;

  *min++ = KEY_INDEX_CH;
  *max++ = KEY_INDEX_CH;

  if (name != NULL) {
    size_t len = strlen(name);

    if (len == 0)
      len++;

    if (len > 63)
      len = 63;

    memcpy(min, name, len);

    min += len;
  } else {
    *min++ = 0x00;
  }

  memset(max, 0xff, 63);

  max += 63;

  iter->min.size = min - iter->min_buf;
  iter->max.size = max - iter->max_buf;
}

void
btc_acctiter_seek(btc_acctiter_t *iter, const char *name) {
  btc_acctiter_preseek(iter, name);
  ldb_iter_seek(iter->it, &iter->min);
  btc_acctiter_update(iter);
}

void
btc_acctiter_seek_gt(btc_acctiter_t *iter, const char *name) {
  btc_acctiter_preseek(iter, name);
  ldb_iter_seek_gt(iter->it, &iter->min);
  btc_acctiter_update(iter);
}

void
btc_acctiter_first(btc_acctiter_t *iter) {
  btc_acctiter_seek(iter, NULL);
}

void
btc_acctiter_next(btc_acctiter_t *iter) {
  ldb_iter_next(iter->it);
  btc_acctiter_update(iter);
}

uint32_t
btc_acctiter_index(btc_acctiter_t *iter) {
  ASSERT(iter->valid);
  return iter->account;
}

const char *
btc_acctiter_key(btc_acctiter_t *iter) {
  ASSERT(iter->valid);
  return iter->name;
}

btc_balance_t *
btc_acctiter_value(btc_acctiter_t *iter) {
  ASSERT(iter->valid);

  if (!db_get_balance(iter->db, iter->account, &iter->balance))
    db_abort("acctiter_value", LDB_CORRUPTION);

  return &iter->balance;
}

/*
 * Address Iterator
 */

struct btc_addriter_s {
  ldb_t *db;
  ldb_iter_t *it;
  btc_address_t addr;
  btc_path_t path;
  uint32_t account;
  int has_account;
  uint8_t min_buf[KEY_APATH_LEN];
  uint8_t max_buf[KEY_APATH_LEN];
  ldb_slice_t min, max;
  uint64_t id;
  int valid;
};

btc_addriter_t *
btc_addriter_create(ldb_t *db) {
  btc_addriter_t *iter = btc_malloc(sizeof(btc_addriter_t));

  memset(iter, 0, sizeof(*iter));

  iter->db = db;
  iter->it = ldb_iterator(db, 0);
  iter->min.data = iter->min_buf;
  iter->max.data = iter->max_buf;

  return iter;
}

void
btc_addriter_destroy(btc_addriter_t *iter) {
  int rc = ldb_iter_status(iter->it);

  if (rc != LDB_OK)
    db_abort("addriter_destroy", rc);

  ldb_iter_destroy(iter->it);

  btc_free(iter);
}

void
btc_addriter_account(btc_addriter_t *iter, uint32_t account) {
  iter->account = account;
  iter->has_account = (account != BTC_NO_ACCOUNT);
}

static void
btc_addriter_parse_key(btc_addriter_t *iter) {
  size_t prefix = 1 + (iter->has_account ? 4 : 0) + 1;
  ldb_slice_t key = ldb_iter_key(iter->it);
  const uint8_t *hash = key.data;
  size_t size = key.size;

  if (size < prefix + 2 || size > prefix + 40)
    db_abort("addriter_parse_key", LDB_CORRUPTION);

  hash += prefix;
  size -= prefix;

  iter->addr.type = hash[-1] >> 5;
  iter->addr.version = hash[-1] & 31;
  iter->addr.length = size;

  memcpy(iter->addr.hash, hash, size);
}

static void
btc_addriter_update(btc_addriter_t *iter) {
  iter->valid = ldb_iter_valid(iter->it);

  if (iter->valid) {
    iter->valid = ldb_iter_compare(iter->it, &iter->max) <= 0;

    if (iter->valid)
      btc_addriter_parse_key(iter);
  }
}

int
btc_addriter_valid(btc_addriter_t *iter) {
  return iter->valid;
}

static void
btc_addriter_preseek(btc_addriter_t *iter, const btc_address_t *target) {
  uint8_t *min = iter->min_buf;
  uint8_t *max = iter->max_buf;
  int ch;

  if (iter->has_account)
    ch = KEY_APATH_CH;
  else
    ch = KEY_PATH_CH;

  *min++ = ch;
  *max++ = ch;

  if (iter->has_account) {
    btc_write32be(min, iter->account);
    btc_write32be(max, iter->account);

    min += 4;
    max += 4;
  }

  if (target != NULL) {
    *min++ = (target->type << 5) | target->version;
    memcpy(min, target->hash, target->length);
    min += target->length;
  } else {
    memset(min, 0x00, 3);
    min += 3;
  }

  memset(max, 0xff, 41);

  max += 41;

  iter->min.size = min - iter->min_buf;
  iter->max.size = max - iter->max_buf;
}

void
btc_addriter_seek(btc_addriter_t *iter, const btc_address_t *target) {
  btc_addriter_preseek(iter, target);
  ldb_iter_seek(iter->it, &iter->min);
  btc_addriter_update(iter);
}

void
btc_addriter_seek_gt(btc_addriter_t *iter, const btc_address_t *target) {
  btc_addriter_preseek(iter, target);
  ldb_iter_seek_gt(iter->it, &iter->min);
  btc_addriter_update(iter);
}

void
btc_addriter_first(btc_addriter_t *iter) {
  btc_addriter_seek(iter, NULL);
}

void
btc_addriter_next(btc_addriter_t *iter) {
  ldb_iter_next(iter->it);
  btc_addriter_update(iter);
}

btc_address_t *
btc_addriter_key(btc_addriter_t *iter) {
  ASSERT(iter->valid);
  return &iter->addr;
}

btc_path_t *
btc_addriter_value(btc_addriter_t *iter) {
  ASSERT(iter->valid);

  if (iter->has_account) {
    if (!db_get_path(iter->db, &iter->addr, &iter->path))
      db_abort("addriter_value", LDB_CORRUPTION);
  } else {
    ldb_slice_t val = ldb_iter_val(iter->it);

    if (!btc_path_import(&iter->path, val.data, val.size))
      db_abort("addriter_value", LDB_CORRUPTION);
  }

  return &iter->path;
}

/*
 * Coin Iterator
 */

struct btc_coiniter_s {
  ldb_t *db;
  ldb_iter_t *it;
  btc_outpoint_t prevout;
  btc_coin_t *coin;
  uint32_t account;
  int has_account;
  uint8_t min_buf[KEY_ACOIN_LEN];
  uint8_t max_buf[KEY_ACOIN_LEN];
  ldb_slice_t min, max;
  uint64_t id;
  int valid;
};

btc_coiniter_t *
btc_coiniter_create(ldb_t *db) {
  btc_coiniter_t *iter = btc_malloc(sizeof(btc_coiniter_t));

  memset(iter, 0, sizeof(*iter));

  iter->db = db;
  iter->it = ldb_iterator(db, 0);
  iter->min.data = iter->min_buf;
  iter->max.data = iter->max_buf;

  return iter;
}

void
btc_coiniter_destroy(btc_coiniter_t *iter) {
  int rc = ldb_iter_status(iter->it);

  if (rc != LDB_OK)
    db_abort("coiniter_destroy", rc);

  if (iter->coin != NULL)
    btc_coin_destroy(iter->coin);

  ldb_iter_destroy(iter->it);

  btc_free(iter);
}

void
btc_coiniter_account(btc_coiniter_t *iter, uint32_t account) {
  iter->account = account;
  iter->has_account = (account != BTC_NO_ACCOUNT);
}

static void
btc_coiniter_parse_key(btc_coiniter_t *iter) {
  size_t prefix = 1 + (iter->has_account ? 4 : 0);
  ldb_slice_t key = ldb_iter_key(iter->it);
  const uint8_t *hash = key.data;

  if (key.size != prefix + 36)
    db_abort("coiniter_parse_key", LDB_CORRUPTION);

  hash += prefix;

  btc_hash_copy(iter->prevout.hash, hash);

  iter->prevout.index = btc_read32be(hash + 32);
}

static void
btc_coiniter_update(btc_coiniter_t *iter) {
  iter->valid = ldb_iter_valid(iter->it);

  if (iter->valid) {
    iter->valid = ldb_iter_compare(iter->it, &iter->max) <= 0;

    if (iter->valid)
      btc_coiniter_parse_key(iter);
  }
}

int
btc_coiniter_valid(btc_coiniter_t *iter) {
  return iter->valid;
}

static void
btc_coiniter_preseek(btc_coiniter_t *iter, const btc_outpoint_t *target) {
  uint8_t *min = iter->min_buf;
  uint8_t *max = iter->max_buf;
  int ch;

  if (iter->has_account)
    ch = KEY_ACOIN_CH;
  else
    ch = KEY_COIN_CH;

  *min++ = ch;
  *max++ = ch;

  if (iter->has_account) {
    btc_write32be(min, iter->account);
    btc_write32be(max, iter->account);

    min += 4;
    max += 4;
  }

  if (target != NULL) {
    memcpy(min, target->hash, 32);
    btc_write32be(min + 32, target->index);
  } else {
    memset(min, 0x00, 36);
  }

  memset(max, 0xff, 36);

  min += 36;
  max += 36;

  iter->min.size = min - iter->min_buf;
  iter->max.size = max - iter->max_buf;
}

void
btc_coiniter_seek(btc_coiniter_t *iter, const btc_outpoint_t *target) {
  btc_coiniter_preseek(iter, target);
  ldb_iter_seek(iter->it, &iter->min);
  btc_coiniter_update(iter);
}

void
btc_coiniter_seek_gt(btc_coiniter_t *iter, const btc_outpoint_t *target) {
  btc_coiniter_preseek(iter, target);
  ldb_iter_seek_gt(iter->it, &iter->min);
  btc_coiniter_update(iter);
}

void
btc_coiniter_first(btc_coiniter_t *iter) {
  btc_coiniter_seek(iter, NULL);
}

void
btc_coiniter_next(btc_coiniter_t *iter) {
  ldb_iter_next(iter->it);
  btc_coiniter_update(iter);
}

btc_outpoint_t *
btc_coiniter_key(btc_coiniter_t *iter) {
  ASSERT(iter->valid);
  return &iter->prevout;
}

btc_coin_t *
btc_coiniter_value(btc_coiniter_t *iter) {
  ASSERT(iter->valid);

  if (iter->coin != NULL)
    btc_coin_destroy(iter->coin);

  if (iter->has_account) {
    btc_outpoint_t *op = &iter->prevout;

    if (!db_get_coin(iter->db, op->hash, op->index, &iter->coin))
      db_abort("coiniter_value", LDB_CORRUPTION);
  } else {
    ldb_slice_t val = ldb_iter_val(iter->it);

    iter->coin = btc_credit_decode(val.data, val.size);

    if (iter->coin == NULL)
      db_abort("coiniter_value", LDB_CORRUPTION);
  }

  return iter->coin;
}

/*
 * Transaction Iterator
 */

struct btc_txiter_s {
  ldb_t *db;
  ldb_iter_t *it;
  btc_tx_t *tx;
  btc_txmeta_t meta;
  int32_t height;
  uint32_t account;
  uint32_t start;
  int has_account;
  int has_start;
  uint8_t min_buf[KEY_MAX_LEN];
  uint8_t max_buf[KEY_MAX_LEN];
  ldb_slice_t min, max;
  uint64_t id;
  const uint8_t *hash;
  int valid;
};

btc_txiter_t *
btc_txiter_create(ldb_t *db) {
  btc_txiter_t *iter = btc_malloc(sizeof(btc_txiter_t));

  memset(iter, 0, sizeof(*iter));

  iter->db = db;
  iter->it = ldb_iterator(db, 0);
  iter->hash = iter->min_buf;
  iter->min.data = iter->min_buf;
  iter->max.data = iter->max_buf;

  return iter;
}

void
btc_txiter_destroy(btc_txiter_t *iter) {
  int rc = ldb_iter_status(iter->it);

  if (rc != LDB_OK)
    db_abort("txiter_destroy", rc);

  if (iter->tx != NULL)
    btc_tx_destroy(iter->tx);

  ldb_iter_destroy(iter->it);

  btc_free(iter);
}

void
btc_txiter_account(btc_txiter_t *iter, uint32_t account) {
  iter->account = account;
  iter->has_account = (account != BTC_NO_ACCOUNT);
}

void
btc_txiter_start(btc_txiter_t *iter, uint32_t height) {
  iter->start = height;
  iter->has_start = 1;
}

static void
btc_txiter_parse_key(btc_txiter_t *iter) {
  ldb_slice_t key = ldb_iter_key(iter->it);
  ldb_slice_t val = ldb_iter_val(iter->it);
  const uint8_t *kp = key.data;
  size_t expect = 1;

  if (iter->has_account)
    expect += 4;

  if (iter->has_start)
    expect += 4;

  expect += 8;

  if (key.size != expect)
    db_abort("txiter_parse_key", LDB_CORRUPTION);

  if (val.size != 32)
    db_abort("txiter_parse_key", LDB_CORRUPTION);

  kp += 1;

  if (iter->has_account)
    kp += 4;

  if (iter->has_start) {
    iter->height = btc_read32be(kp);
    kp += 4;
  }

  iter->id = btc_read64be(kp);
  iter->hash = val.data;
}

static void
btc_txiter_update(btc_txiter_t *iter, int direction) {
  iter->valid = ldb_iter_valid(iter->it);

  if (iter->valid) {
    if (direction < 0)
      iter->valid = ldb_iter_compare(iter->it, &iter->min) >= 0;
    else
      iter->valid = ldb_iter_compare(iter->it, &iter->max) <= 0;

    if (iter->valid)
      btc_txiter_parse_key(iter);
  }
}

int
btc_txiter_valid(btc_txiter_t *iter) {
  return iter->valid;
}

static void
btc_txiter_preseek(btc_txiter_t *iter, uint64_t id, int direction) {
  uint8_t *min = iter->min_buf;
  uint8_t *max = iter->max_buf;
  int ch;

  if (iter->has_account && iter->has_start)
    ch = KEY_AHEIGHT_CH;
  else if (iter->has_start)
    ch = KEY_HEIGHT_CH;
  else if (iter->has_account)
    ch = KEY_ATXID_CH;
  else
    ch = KEY_TXID_CH;

  *min++ = ch;
  *max++ = ch;

  if (iter->has_account) {
    btc_write32be(min, iter->account);
    btc_write32be(max, iter->account);

    min += 4;
    max += 4;
  }

  if (iter->has_start) {
    if (direction < 0) {
      btc_write32be(min, 0);
      btc_write32be(max, iter->start);
    } else {
      btc_write32be(min, iter->start);
      btc_write32be(max, UINT32_MAX);
    }

    min += 4;
    max += 4;
  }

  if (direction < 0) {
    btc_write64be(min, 0);
    btc_write64be(max, id);
  } else {
    btc_write64be(min, id);
    btc_write64be(max, UINT64_MAX);
  }

  min += 8;
  max += 8;

  iter->min.size = min - iter->min_buf;
  iter->max.size = max - iter->max_buf;
}

void
btc_txiter_seek(btc_txiter_t *iter, uint64_t id) {
  btc_txiter_seek_ge(iter, id);
}

void
btc_txiter_seek_ge(btc_txiter_t *iter, uint64_t id) {
  btc_txiter_preseek(iter, id, 1);
  ldb_iter_seek_ge(iter->it, &iter->min);
  btc_txiter_update(iter, 1);
}

void
btc_txiter_seek_gt(btc_txiter_t *iter, uint64_t id) {
  btc_txiter_preseek(iter, id, 1);
  ldb_iter_seek_gt(iter->it, &iter->min);
  btc_txiter_update(iter, 1);
}

void
btc_txiter_seek_le(btc_txiter_t *iter, uint64_t id) {
  btc_txiter_preseek(iter, id, -1);
  ldb_iter_seek_le(iter->it, &iter->max);
  btc_txiter_update(iter, -1);
}

void
btc_txiter_seek_lt(btc_txiter_t *iter, uint64_t id) {
  btc_txiter_preseek(iter, id, -1);
  ldb_iter_seek_lt(iter->it, &iter->max);
  btc_txiter_update(iter, -1);
}

void
btc_txiter_first(btc_txiter_t *iter) {
  btc_txiter_seek_ge(iter, 0);
}

void
btc_txiter_last(btc_txiter_t *iter) {
  btc_txiter_seek_le(iter, UINT64_MAX);
}

void
btc_txiter_next(btc_txiter_t *iter) {
  ldb_iter_next(iter->it);
  btc_txiter_update(iter, 1);
}

void
btc_txiter_prev(btc_txiter_t *iter) {
  ldb_iter_prev(iter->it);
  btc_txiter_update(iter, -1);
}

int
btc_txiter_compare(const btc_txiter_t *iter, uint64_t key) {
  ASSERT(iter->valid);
  return (iter->id > key) - (iter->id < key);
}

int32_t
btc_txiter_height(const btc_txiter_t *iter) {
  ASSERT(iter->valid && iter->has_start);
  return (int32_t)iter->height;
}

const uint8_t *
btc_txiter_hash(const btc_txiter_t *iter) {
  ASSERT(iter->valid);
  return iter->hash;
}

uint64_t
btc_txiter_key(const btc_txiter_t *iter) {
  ASSERT(iter->valid);
  return iter->id;
}

btc_txmeta_t *
btc_txiter_meta(btc_txiter_t *iter) {
  ASSERT(iter->valid);

  if (!db_get_txmeta(iter->db, iter->hash, &iter->meta))
    db_abort("txiter_meta", LDB_CORRUPTION);

  return &iter->meta;
}

btc_tx_t *
btc_txiter_value(btc_txiter_t *iter) {
  ASSERT(iter->valid);

  if (iter->tx != NULL)
    btc_tx_destroy(iter->tx);

  if (!db_get_tx(iter->db, iter->hash, &iter->tx))
    db_abort("txiter_value", LDB_CORRUPTION);

  return iter->tx;
}
