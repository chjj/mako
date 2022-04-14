/*!
 * record.c - wallet records for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <mako/bip32.h>
#include <mako/coins.h>
#include <mako/entry.h>
#include <mako/map.h>
#include <mako/network.h>
#include <mako/util.h>

#include "../impl.h"
#include "../internal.h"

#include "record.h"

/*
 * Balance
 */

DEFINE_SERIALIZABLE_OBJECT(btc_balance, extern)

void
btc_balance_init(btc_balance_t *balance) {
  balance->tx = 0;
  balance->coin = 0;
  balance->confirmed = 0;
  balance->unconfirmed = 0;
}

void
btc_balance_clear(btc_balance_t *balance) {
  (void)balance;
}

void
btc_balance_copy(btc_balance_t *z, const btc_balance_t *x) {
  *z = *x;
}

void
btc_balance_apply(btc_balance_t *z, const btc_balance_t *x) {
  z->tx += x->tx;
  z->coin += x->coin;
  z->confirmed += x->confirmed;
  z->unconfirmed += x->unconfirmed;
}

void
btc_balance_unapply(btc_balance_t *z, const btc_balance_t *x) {
  z->tx -= x->tx;
  z->coin -= x->coin;
  z->confirmed -= x->confirmed;
  z->unconfirmed -= x->unconfirmed;
}

size_t
btc_balance_size(const btc_balance_t *balance) {
  (void)balance;
  return 32;
}

uint8_t *
btc_balance_write(uint8_t *zp, const btc_balance_t *x) {
  zp = btc_int64_write(zp, x->tx);
  zp = btc_int64_write(zp, x->coin);
  zp = btc_int64_write(zp, x->confirmed);
  zp = btc_int64_write(zp, x->unconfirmed);
  return zp;
}

int
btc_balance_read(btc_balance_t *z, const uint8_t **xp, size_t *xn) {
  if (!btc_int64_read(&z->tx, xp, xn))
    return 0;

  if (!btc_int64_read(&z->coin, xp, xn))
    return 0;

  if (!btc_int64_read(&z->confirmed, xp, xn))
    return 0;

  if (!btc_int64_read(&z->unconfirmed, xp, xn))
    return 0;

  return 1;
}

/*
 * Balance Delta
 */

void
btc_delta_init(btc_delta_t *delta) {
  btc_balance_init(&delta->balance);
  btc_balance_init(&delta->watched);
  btc_intmap_init(&delta->map);

  delta->updated = 0;
}

void
btc_delta_clear(btc_delta_t *delta) {
  btc_mapiter_t it;

  btc_map_each(&delta->map, it)
    btc_balance_destroy(delta->map.vals[it]);

  btc_intmap_clear(&delta->map);
}

btc_balance_t *
btc_delta_get(btc_delta_t *delta, uint32_t account) {
  btc_mapiter_t it;
  int exists;

  it = btc_intmap_insert(&delta->map, account, &exists);

  if (!exists)
    delta->map.vals[it] = btc_balance_create();

  return delta->map.vals[it];
}

void
btc_delta_tx(btc_delta_t *delta, const btc_path_t *path, int64_t value) {
  btc_delta_get(delta, path->account)->tx = value;

  if (!(path->account & BTC_BIP32_HARDEN))
    delta->balance.tx = value;
  else
    delta->watched.tx = value;

  delta->updated = 1;
}

void
btc_delta_coin(btc_delta_t *delta, const btc_path_t *path, int64_t value) {
  btc_delta_get(delta, path->account)->coin += value;

  if (!(path->account & BTC_BIP32_HARDEN))
    delta->balance.coin += value;
  else
    delta->watched.coin += value;
}

void
btc_delta_unconf(btc_delta_t *delta, const btc_path_t *path, int64_t value) {
  btc_delta_get(delta, path->account)->unconfirmed += value;

  if (!(path->account & BTC_BIP32_HARDEN))
    delta->balance.unconfirmed += value;
  else
    delta->watched.unconfirmed += value;
}

void
btc_delta_conf(btc_delta_t *delta, const btc_path_t *path, int64_t value) {
  btc_delta_get(delta, path->account)->confirmed += value;

  if (!(path->account & BTC_BIP32_HARDEN))
    delta->balance.confirmed += value;
  else
    delta->watched.confirmed += value;
}

/*
 * BIP32 Serialization
 */

size_t
btc_bip32_size(const btc_hdnode_t *node) {
  (void)node;
  return 75;
}

uint8_t *
btc_bip32_write(uint8_t *zp, const btc_hdnode_t *x) {
  zp = btc_uint8_write(zp, x->type);
  zp = btc_uint8_write(zp, x->depth);
  zp = btc_uint32_write(zp, x->parent);
  zp = btc_uint32_write(zp, x->index);
  zp = btc_raw_write(zp, x->chain, 32);
  zp = btc_raw_write(zp, x->pubkey, 33);
  return zp;
}

int
btc_bip32_read(btc_hdnode_t *z, const uint8_t **xp, size_t *xn) {
  uint8_t type;

  if (!btc_uint8_read(&type, xp, xn))
    return 0;

  z->type = (enum btc_bip32_type)type;

  if (!btc_uint8_read(&z->depth, xp, xn))
    return 0;

  if (!btc_uint32_read(&z->parent, xp, xn))
    return 0;

  if (!btc_uint32_read(&z->index, xp, xn))
    return 0;

  if (!btc_raw_read(z->chain, 32, xp, xn))
    return 0;

  btc_memzero(z->seckey, 32);

  if (!btc_raw_read(z->pubkey, 33, xp, xn))
    return 0;

  return 1;
}

/*
 * Credit
 */

size_t
btc_credit_size(const btc_coin_t *x) {
  return btc_coin_size(x) + 1;
}

uint8_t *
btc_credit_write(uint8_t *zp, const btc_coin_t *x) {
  int flags = (x->spent << 2) | (x->safe << 1) | x->watch;

  zp = btc_coin_write(zp, x);
  zp = btc_uint8_write(zp, flags);

  return zp;
}

int
btc_credit_read(btc_coin_t *z, const uint8_t **xp, size_t *xn) {
  uint8_t flags;

  if (!btc_coin_read(z, xp, xn))
    return 0;

  if (!btc_uint8_read(&flags, xp, xn))
    return 0;

  z->spent = (flags >> 2) & 1;
  z->safe = (flags >> 1) & 1;
  z->watch = (flags >> 0) & 1;

  return 1;
}

size_t
btc_credit_export(uint8_t *zp, const btc_coin_t *x) {
  return btc_credit_write(zp, x) - zp;
}

int
btc_credit_import(btc_coin_t *z, const uint8_t *xp, size_t xn) {
  return btc_credit_read(z, &xp, &xn);
}

void
btc_credit_encode(uint8_t **zp, size_t *zn, const btc_coin_t *x) {
  *zn = btc_credit_size(x);
  *zp = (uint8_t *)btc_malloc(*zn);

  btc_credit_export(*zp, x);
}

btc_coin_t *
btc_credit_decode(const uint8_t *xp, size_t xn) {
  btc_coin_t *z = btc_coin_create();

  if (!btc_credit_import(z, xp, xn)) {
    btc_coin_destroy(z);
    return NULL;
  }

  return z;
}

/*
 * Path
 */

DEFINE_SERIALIZABLE_OBJECT(btc_path, extern)

btc_path_t
btc_path(uint32_t account, uint32_t change, uint32_t index) {
  btc_path_t path;

  path.account = account;
  path.change = change;
  path.index = index;

  return path;
}

void
btc_path_init(btc_path_t *path) {
  path->account = 0;
  path->change = 0;
  path->index = 0;
}

void
btc_path_clear(btc_path_t *path) {
  (void)path;
}

void
btc_path_copy(btc_path_t *z, const btc_path_t *x) {
  *z = *x;
}

size_t
btc_path_size(const btc_path_t *path) {
  (void)path;
  return 12;
}

uint8_t *
btc_path_write(uint8_t *zp, const btc_path_t *path) {
  zp = btc_uint32_write(zp, path->account);
  zp = btc_uint32_write(zp, path->change);
  zp = btc_uint32_write(zp, path->index);
  return zp;
}

int
btc_path_read(btc_path_t *path, const uint8_t **xp, size_t *xn) {
  if (!btc_uint32_read(&path->account, xp, xn))
    return 0;

  if (!btc_uint32_read(&path->change, xp, xn))
    return 0;

  if (!btc_uint32_read(&path->index, xp, xn))
    return 0;

  return 1;
}

/*
 * Sync State
 */

void
btc_state_init(btc_state_t *state, const btc_network_t *network) {
  state->start_height = 0;
  btc_hash_copy(state->start_hash, network->genesis.hash);
  state->height = 0;
  state->marked = 0;
}

void
btc_state_set(btc_state_t *state, const btc_entry_t *entry) {
  state->start_height = entry->height;
  btc_hash_copy(state->start_hash, entry->hash);
  state->height = entry->height;
  state->marked = 0;
}

size_t
btc_state_size(const btc_state_t *state) {
  (void)state;
  return 41;
}

uint8_t *
btc_state_write(uint8_t *zp, const btc_state_t *x) {
  zp = btc_int32_write(zp, x->start_height);
  zp = btc_raw_write(zp, x->start_hash, 32);
  zp = btc_int32_write(zp, x->height);
  zp = btc_uint8_write(zp, x->marked);
  return zp;
}

int
btc_state_read(btc_state_t *z, const uint8_t **xp, size_t *xn) {
  if (!btc_int32_read(&z->start_height, xp, xn))
    return 0;

  if (!btc_raw_read(z->start_hash, 32, xp, xn))
    return 0;

  if (!btc_int32_read(&z->height, xp, xn))
    return 0;

  if (!btc_uint8_read(&z->marked, xp, xn))
    return 0;

  return 1;
}

size_t
btc_state_export(uint8_t *zp, const btc_state_t *x) {
  return btc_state_write(zp, x) - zp;
}

int
btc_state_import(btc_state_t *z, const uint8_t *xp, size_t xn) {
  return btc_state_read(z, &xp, &xn);
}

/*
 * Transaction Metadata
 */

void
btc_txmeta_init(btc_txmeta_t *meta) {
  meta->id = 0;
  meta->height = -1;
  meta->time = 0;
  meta->mtime = 0;
  meta->index = -1;
  meta->resolved = 0;
  meta->inpval = 0;

  btc_hash_init(meta->block);
}

void
btc_txmeta_set(btc_txmeta_t *meta,
               uint64_t id,
               const btc_entry_t *entry,
               int32_t index) {
  if (entry != NULL) {
    meta->id = id;
    meta->height = entry->height;
    meta->time = entry->header.time;
    meta->mtime = btc_now();
    meta->index = index;
    meta->resolved = 0;
    meta->inpval = 0;

    btc_hash_copy(meta->block, entry->hash);
  } else {
    btc_txmeta_init(meta);

    meta->id = id;
    meta->mtime = btc_now();
  }
}

void
btc_txmeta_set_block(btc_txmeta_t *meta,
                     const btc_entry_t *entry,
                     int32_t index) {
  if (entry != NULL) {
    meta->height = entry->height;
    meta->time = entry->header.time;
    meta->index = index;

    btc_hash_copy(meta->block, entry->hash);
  } else {
    meta->height = -1;
    meta->time = 0;
    meta->index = -1;

    btc_hash_init(meta->block);
  }
}

size_t
btc_txmeta_size(const btc_txmeta_t *txmeta) {
  (void)txmeta;
  return 76;
}

uint8_t *
btc_txmeta_write(uint8_t *zp, const btc_txmeta_t *x) {
  zp = btc_uint64_write(zp, x->id);
  zp = btc_int32_write(zp, x->height);
  zp = btc_int64_write(zp, x->time);
  zp = btc_int64_write(zp, x->mtime);
  zp = btc_int32_write(zp, x->index);
  zp = btc_raw_write(zp, x->block, 32);
  zp = btc_uint32_write(zp, x->resolved);
  zp = btc_int64_write(zp, x->inpval);
  return zp;
}

int
btc_txmeta_read(btc_txmeta_t *z, const uint8_t **xp, size_t *xn) {
  if (!btc_uint64_read(&z->id, xp, xn))
    return 0;

  if (!btc_int32_read(&z->height, xp, xn))
    return 0;

  if (!btc_int64_read(&z->time, xp, xn))
    return 0;

  if (!btc_int64_read(&z->mtime, xp, xn))
    return 0;

  if (!btc_int32_read(&z->index, xp, xn))
    return 0;

  if (!btc_raw_read(z->block, 32, xp, xn))
    return 0;

  if (!btc_uint32_read(&z->resolved, xp, xn))
    return 0;

  if (!btc_int64_read(&z->inpval, xp, xn))
    return 0;

  return 1;
}

size_t
btc_txmeta_export(uint8_t *zp, const btc_txmeta_t *x) {
  return btc_txmeta_write(zp, x) - zp;
}

int
btc_txmeta_import(btc_txmeta_t *z, const uint8_t *xp, size_t xn) {
  return btc_txmeta_read(z, &xp, &xn);
}
