/*!
 * account.c - wallet account for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <mako/address.h>
#include <mako/bip32.h>
#include <mako/bloom.h>
#include <mako/script.h>
#include <mako/util.h>

#include "../impl.h"
#include "../internal.h"

#include "account.h"
#include "database.h"
#include "record.h"

/*
 * Account
 */

void
btc_account_init(btc_account_t *acct, btc_bloom_t *filter) {
  strcpy(acct->name, "default");

  acct->index = 0;
  acct->watch_only = 0;
  acct->receive_index = 0;
  acct->change_index = 0;
  acct->lookahead = 100;

  btc_hdpub_init(&acct->key);

  acct->filter = filter;
}

void
btc_account_clear(btc_account_t *acct) {
  btc_hdpub_clear(&acct->key);
}

size_t
btc_account_size(const btc_account_t *acct) {
  return btc_string_size(acct->name) + 17 + btc_bip32_size(&acct->key);
}

uint8_t *
btc_account_write(uint8_t *zp, const btc_account_t *x) {
  zp = btc_string_write(zp, x->name);
  zp = btc_uint32_write(zp, x->index);
  zp = btc_uint32_write(zp, x->receive_index);
  zp = btc_uint32_write(zp, x->change_index);
  zp = btc_uint32_write(zp, x->lookahead);
  zp = btc_uint8_write(zp, x->watch_only);
  zp = btc_bip32_write(zp, &x->key);
  return zp;
}

int
btc_account_read(btc_account_t *z, const uint8_t **xp, size_t *xn) {
  if (!btc_string_read(z->name, sizeof(z->name), xp, xn))
    return 0;

  if (!btc_uint32_read(&z->index, xp, xn))
    return 0;

  if (!btc_uint32_read(&z->receive_index, xp, xn))
    return 0;

  if (!btc_uint32_read(&z->change_index, xp, xn))
    return 0;

  if (!btc_uint32_read(&z->lookahead, xp, xn))
    return 0;

  if (!btc_uint8_read(&z->watch_only, xp, xn))
    return 0;

  if (!btc_bip32_read(&z->key, xp, xn))
    return 0;

  return 1;
}

size_t
btc_account_export(uint8_t *zp, const btc_account_t *x) {
  return btc_account_write(zp, x) - zp;
}

int
btc_account_import(btc_account_t *z, const uint8_t *xp, size_t xn) {
  return btc_account_read(z, &xp, &xn);
}

int
btc_account_import_name(char *name, size_t size, const uint8_t *xp, size_t xn) {
  return btc_string_read(name, size, &xp, &xn);
}

void
btc_account_leaf(btc_hdnode_t *leaf,
                 const btc_account_t *acct,
                 uint32_t change,
                 uint32_t index) {
  CHECK(btc_hdpub_leaf(leaf, &acct->key, change, index));
}

void
btc_account_address(btc_address_t *addr,
                    const btc_account_t *acct,
                    uint32_t change,
                    uint32_t index) {
  btc_hdnode_t key;

  btc_account_leaf(&key, acct, change, index);

  switch (key.type) {
    case BTC_BIP32_STANDARD: {
      btc_address_set_p2pk(addr, key.pubkey, 33);
      break;
    }

    case BTC_BIP32_P2WPKH: {
      btc_address_set_p2wpk(addr, key.pubkey, 33);
      break;
    }

    case BTC_BIP32_NESTED_P2WPKH: {
      btc_script_t script;
      uint8_t hash[20];

      btc_script_init(&script);
      btc_address_set_p2wpk(addr, key.pubkey, 33);
      btc_address_get_script(&script, addr);
      btc_script_hash160(hash, &script);
      btc_address_set_p2sh(addr, hash);
      btc_script_clear(&script);

      break;
    }

    default: {
      btc_abort();
      break;
    }
  }
}

void
btc_account_receive(btc_address_t *addr, const btc_account_t *acct) {
  btc_account_address(addr, acct, 0, acct->receive_index);
}

void
btc_account_change(btc_address_t *addr, const btc_account_t *acct) {
  btc_account_address(addr, acct, 1, acct->change_index);
}

void
btc_account_path(const btc_account_t *acct,
                 ldb_batch_t *batch,
                 uint32_t change,
                 uint32_t index) {
  btc_path_t path = btc_path(acct->index, change, index);
  btc_address_t addr;

  btc_account_address(&addr, acct, change, index);

  db_put_path(batch, &addr, &path);
  db_put_apath(batch, acct->index, &addr);

  if (acct->filter != NULL)
    btc_bloom_add(acct->filter, addr.hash, addr.length);
}

void
btc_account_setup(const btc_account_t *acct, ldb_batch_t *batch) {
  static const btc_balance_t bal = {0, 0, 0, 0};
  uint32_t i;

  db_put_account(batch, acct->index, acct);
  db_put_balance(batch, acct->index, &bal);
  db_put_index(batch, acct->name, acct->index);

  for (i = 0; i < acct->lookahead + 1; i++) {
    btc_account_path(acct, batch, 0, i);
    btc_account_path(acct, batch, 1, i);
  }
}

void
btc_account_sync(btc_account_t *acct,
                 ldb_batch_t *batch,
                 uint32_t receive,
                 uint32_t change) {
  uint32_t lookahead = acct->lookahead;
  uint32_t update = 0;
  uint32_t i;

  if (receive >= acct->receive_index) {
    for (i = acct->receive_index; i <= receive; i++)
      btc_account_path(acct, batch, 0, i + lookahead + 1);

    acct->receive_index = i;

    update = 1;
  }

  if (change >= acct->change_index) {
    for (i = acct->change_index; i <= change; i++)
      btc_account_path(acct, batch, 1, i + lookahead + 1);

    acct->change_index = i;

    update = 1;
  }

  if (update)
    db_put_account(batch, acct->index, acct);
}

void
btc_account_next(btc_account_t *acct, ldb_batch_t *batch) {
  acct->receive_index++;

  btc_account_path(acct, batch, 0, acct->receive_index + acct->lookahead);

  db_put_account(batch, acct->index, acct);
}

void
btc_account_prev(btc_account_t *acct, ldb_batch_t *batch) {
  if (acct->receive_index == 0)
    return;

  acct->receive_index--;

  db_put_account(batch, acct->index, acct);
}

void
btc_account_generate(btc_account_t *acct,
                     ldb_batch_t *batch,
                     const char *name,
                     const btc_master_t *master,
                     uint32_t index) {
  btc_hdnode_t node;

  CHECK(btc_strcpy(acct->name, sizeof(acct->name), name));
  CHECK(btc_master_account(&node, master, index));

  acct->index = index;

  btc_hdpub_copy(&acct->key, &node);

  btc_account_setup(acct, batch);

  btc_hdpriv_clear(&node);
}

void
btc_account_watch(btc_account_t *acct,
                  ldb_batch_t *batch,
                  const char *name,
                  const btc_hdnode_t *node,
                  uint32_t index) {
  CHECK(btc_strcpy(acct->name, sizeof(acct->name), name));

  acct->index = index | BTC_BIP32_HARDEN;
  acct->watch_only = 1;

  btc_hdpub_copy(&acct->key, node);

  btc_account_setup(acct, batch);
}
