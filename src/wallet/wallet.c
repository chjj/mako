/*!
 * wallet.c - wallet for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mako/address.h>
#include <mako/bip32.h>
#include <mako/bip39.h>
#include <mako/block.h>
#include <mako/bloom.h>
#include <mako/coins.h>
#include <mako/map.h>
#include <mako/network.h>
#include <mako/policy.h>
#include <mako/printf.h>
#include <mako/script.h>
#include <mako/select.h>
#include <mako/tx.h>
#include <mako/util.h>
#include <mako/vector.h>

#include "../bio.h"
#include "../impl.h"
#include "../internal.h"

#include "account.h"
#include "client.h"
#include "database.h"
#include "iterator.h"
#include "master.h"
#include "record.h"
#include "txdb.h"
#include "wallet.h"

/*
 * Constants
 */

enum {
  LOG_NONE = 0,
  LOG_ERROR = 1,
  LOG_WARN = 2,
  LOG_INFO = 3,
  LOG_DEBUG = 4,
  LOG_SPAM = 5
};

/*
 * Wallet Options
 */

static const btc_walopt_t walopt_default = {
  /* .client = */ NULL,
  /* .checkpoints = */ 1,
  /* .type = */ BTC_BIP32_P2WPKH,
  /* .mnemonic = */ NULL,
  /* .chain = */ NULL
};

const btc_walopt_t *btc_walopt_default = &walopt_default;

/*
 * Wallet
 */

btc_wallet_t *
btc_wallet_create(const btc_network_t *network, const btc_walopt_t *options) {
  btc_wallet_t *wallet = btc_malloc(sizeof(btc_wallet_t));

  if (options == NULL)
    options = btc_walopt_default;

  wallet->network = network;
  wallet->options = *options;

  if (options->client != NULL) {
    wallet->client = *options->client;
    wallet->options.client = &wallet->client;
  } else {
    btc_wclient_init(&wallet->client);
    wallet->options.client = NULL;
  }

  if (options->mnemonic != NULL) {
    wallet->mnemonic_tmp = *options->mnemonic;
    wallet->options.mnemonic = &wallet->mnemonic_tmp;
  } else {
    btc_mnemonic_init(&wallet->mnemonic_tmp);
    wallet->options.mnemonic = NULL;
  }

  if (options->chain != NULL) {
    wallet->chain_tmp = *options->chain;
    wallet->options.type = options->chain->type;
    wallet->options.chain = &wallet->chain_tmp;
  } else {
    btc_hdpriv_init(&wallet->chain_tmp);
    wallet->options.chain = NULL;
  }

  btc_outset_init(&wallet->frozen);

  wallet->rate = 10000;
  wallet->db = NULL;
  wallet->cache = NULL;

  btc_state_init(&wallet->state, wallet->network);
  btc_bloom_init(&wallet->filter);

  wallet->account_index = 0;
  wallet->watch_index = 0;
  wallet->unique_id = 0;

  btc_balance_init(&wallet->balance);
  btc_balance_init(&wallet->watched);
  btc_master_init(&wallet->master, network);

  return wallet;
}

void
btc_wallet_destroy(btc_wallet_t *wallet) {
  btc_mapiter_t it;

  btc_map_each(&wallet->frozen, it)
    btc_outpoint_destroy(wallet->frozen.keys[it]);

  btc_master_clear(&wallet->master);
  btc_bloom_clear(&wallet->filter);
  btc_outset_clear(&wallet->frozen);
  btc_hdpriv_clear(&wallet->chain_tmp);
  btc_mnemonic_clear(&wallet->mnemonic_tmp);

  btc_free(wallet);
}

static void
btc_log(btc_wallet_t *wallet, int level, const char *fmt, ...) {
  const btc_wclient_t *client = &wallet->client;
  va_list ap;

  va_start(ap, fmt);

  if (client->log != NULL) {
    client->log(client->state, level, fmt, ap);
  } else {
    btc_vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
  }

  va_end(ap);
}

static int
btc_wallet_load_database(btc_wallet_t *wallet, const char *path) {
  ldb_dbopt_t options = *ldb_dbopt_default;
  int rc;

  wallet->cache = ldb_lru_create(8 << 20);

  options.create_if_missing = 1;
  options.block_cache = wallet->cache;
  options.write_buffer_size = 4 << 20;
  options.compression = LDB_NO_COMPRESSION;
  options.filter_policy = ldb_bloom_default;
  options.max_open_files = 125;
  options.use_mmap = 0;

  rc = ldb_open(path, &options, &wallet->db);

  if (rc != LDB_OK) {
    btc_log(wallet, LOG_ERROR, "ldb_open: %s", ldb_strerror(rc));
    ldb_lru_destroy(wallet->cache);
    wallet->cache = NULL;
    return 0;
  }

  return 1;
}

static void
btc_wallet_unload_database(btc_wallet_t *wallet) {
  ldb_close(wallet->db);
  ldb_lru_destroy(wallet->cache);

  wallet->db = NULL;
  wallet->cache = NULL;
}

static int
btc_wallet_load_flags(btc_wallet_t *wallet) {
  uint32_t magic, flags;
  ldb_batch_t batch;

  if (!db_get_flags(wallet->db, &magic, &flags)) {
    db_batch(&batch);
    db_put_flags(&batch, wallet->network->magic, 0);
    db_write(wallet->db, &batch);
    return 1;
  }

  if (magic != wallet->network->magic) {
    btc_log(wallet, LOG_ERROR, "Network mismatch for wallet.");
    return 0;
  }

  return 1;
}

static int
btc_wallet_init_state(btc_wallet_t *wallet) {
  const btc_wclient_t *client = &wallet->client;
  ldb_batch_t batch;

  db_batch(&batch);

  btc_log(wallet, LOG_INFO, "Initializing database state.");

  if (wallet->options.client) {
    const btc_entry_t *entry = btc_wclient_tip(client);
    int32_t left = wallet->network->block.keep_blocks;

    btc_state_set(&wallet->state, entry);

    while (entry != NULL && left != 0) {
      db_put_block(&batch, entry->height, entry->hash);

      if (entry->height == 0)
        break;

      entry = btc_wclient_by_height(client, entry->height - 1);
      left--;
    }
  } else {
    btc_state_init(&wallet->state, wallet->network);
    db_put_block(&batch, 0, wallet->network->genesis.hash);
  }

  if (wallet->options.checkpoints && (wallet->options.mnemonic ||
                                      wallet->options.chain)) {
    wallet->state.marked = 1;
  }

  db_put_state(&batch, &wallet->state);

  db_write(wallet->db, &batch);

  return 1;
}

static int
btc_wallet_load_state(btc_wallet_t *wallet) {
  if (!db_get_state(wallet->db, &wallet->state))
    return btc_wallet_init_state(wallet);

  return 1;
}

static void
btc_wallet_unload_state(btc_wallet_t *wallet) {
  btc_state_init(&wallet->state, wallet->network);
}

static int
btc_wallet_init_data(btc_wallet_t *wallet) {
  btc_account_t acct;
  ldb_batch_t batch;

  switch (wallet->options.type) {
    case BTC_BIP32_STANDARD:
    case BTC_BIP32_P2WPKH:
    case BTC_BIP32_NESTED_P2WPKH:
      break;
    default:
      return 0;
  }

  if (wallet->options.chain) {
    const btc_hdnode_t *node = wallet->options.chain;

    if (node->depth | node->parent | node->index)
      return 0;

    if (btc_hdpriv_is_null(node))
      return 0;
  }

  wallet->account_index = 0;
  wallet->watch_index = BTC_BIP32_HARDEN - 1;
  wallet->unique_id = 0;

  btc_balance_init(&wallet->balance);
  btc_balance_init(&wallet->watched);

  if (wallet->options.mnemonic) {
    btc_master_import_mnemonic(&wallet->master,
                               wallet->options.type,
                               wallet->options.mnemonic);
    btc_mnemonic_clear(&wallet->mnemonic_tmp);
    wallet->options.mnemonic = NULL;
  } else if (wallet->options.chain) {
    btc_master_import_chain(&wallet->master, wallet->options.chain);
    btc_hdpriv_clear(&wallet->chain_tmp);
    wallet->options.chain = NULL;
  } else {
    btc_master_generate(&wallet->master, wallet->options.type);
  }

  db_batch(&batch);

  btc_account_init(&acct, NULL);
  btc_account_generate(&acct, &batch, "default", &wallet->master, 0);

  db_put_master(&batch, &wallet->master);
  db_put_wallet(&batch, wallet);

  db_write(wallet->db, &batch);

  btc_log(wallet, LOG_INFO, "Wallet initialized.");

  return 1;
}

static int
btc_wallet_load_data(btc_wallet_t *wallet) {
  if (!db_get_wallet(wallet->db, wallet))
    return btc_wallet_init_data(wallet);

  if (!db_get_master(wallet->db, &wallet->master))
    return 0;

  btc_log(wallet, LOG_INFO, "Wallet opened.");

  return 1;
}

static void
btc_wallet_unload_data(btc_wallet_t *wallet) {
  btc_master_clear(&wallet->master);
  btc_master_init(&wallet->master, wallet->network);
}

static int
btc_wallet_load_filter(btc_wallet_t *wallet) {
  size_t alloc = 100000; /* ~2.3mb */
  size_t paths = 0;
  size_t coins = 0;
  size_t items = 0;
  ldb_iter_t *it;

  it = ldb_iterator(wallet->db, 0);

  ldb_iter_range(it, &key_path_min, &key_path_max)
    paths++;

  CHECK(ldb_iter_status(it) == LDB_OK);

  ldb_iter_range(it, &key_coin_min, &key_coin_max)
    coins++;

  CHECK(ldb_iter_status(it) == LDB_OK);

  items = paths + coins;

  if (items > (alloc / 2))
    alloc = items * 2;

  btc_bloom_set(&wallet->filter, alloc, 0.0001, BTC_BLOOM_INTERNAL);

  ldb_iter_range(it, &key_path_min, &key_path_max) {
    ldb_slice_t key = ldb_iter_key(it);
    const uint8_t *hash = (uint8_t *)key.data + 2;
    size_t len = key.size - 2;

    btc_bloom_add(&wallet->filter, hash, len);
  }

  CHECK(ldb_iter_status(it) == LDB_OK);

  ldb_iter_range(it, &key_coin_min, &key_coin_max) {
    ldb_slice_t key = ldb_iter_key(it);
    const uint8_t *hash = (uint8_t *)key.data + 1;
    uint32_t index = btc_read32be(hash + 32);

    btc_wallet_watch(wallet, hash, index);
  }

  CHECK(ldb_iter_status(it) == LDB_OK);

  ldb_iter_destroy(it);

  btc_log(wallet, LOG_INFO, "Added %zu hashes to filter.", paths);
  btc_log(wallet, LOG_INFO, "Added %zu outpoints to filter.", coins);

  return 1;
}

static void
btc_wallet_unload_filter(btc_wallet_t *wallet) {
  btc_bloom_clear(&wallet->filter);
  btc_bloom_init(&wallet->filter);
}

static int
btc_wallet_sync_state(btc_wallet_t *wallet) {
  const btc_wclient_t *client = &wallet->client;
  int32_t height = wallet->state.height;
  uint8_t hash[32];

  if (!wallet->options.client)
    return 1;

  btc_log(wallet, LOG_INFO, "Syncing state from height %d.", height);

  for (;;) {
    if (!db_get_block(wallet->db, height, hash))
      return 0;

    if (btc_wclient_by_hash(client, hash))
      break;

    CHECK(height != 0);
    height -= 1;
  }

  return btc_wallet_rescan(wallet, height);
}

static void
btc_wallet_resend(btc_wallet_t *wallet) {
  const btc_wclient_t *client = &wallet->client;
  btc_txiter_t *it = btc_wallet_txs(wallet);
  int total = 0;

  btc_txiter_start(it, -1);
  btc_txiter_first(it);

  for (; btc_txiter_valid(it); btc_txiter_next(it)) {
    const btc_tx_t *tx = btc_txiter_value(it);

    btc_wclient_send(client, tx);

    total++;
  }

  btc_log(wallet, LOG_INFO, "Rebroadcasted %d transactions.", total);

  btc_txiter_destroy(it);
}

int
btc_wallet_open(btc_wallet_t *wallet, const char *path) {
  const btc_wclient_t *client = &wallet->client;

  if (!btc_wclient_open(client))
    return 0;

  if (!btc_wallet_load_database(wallet, path)) {
    btc_wclient_close(client);
    return 0;
  }

  if (!btc_wallet_load_flags(wallet))
    goto fail;

  if (!btc_wallet_load_state(wallet))
    goto fail;

  if (!btc_wallet_load_data(wallet))
    goto fail;

  if (!btc_wallet_load_filter(wallet))
    goto fail;

  if (!btc_wallet_sync_state(wallet))
    goto fail;

  btc_log(wallet, LOG_INFO, "Wallet loaded (height=%d, start=%d).",
                            wallet->state.height,
                            wallet->state.start_height);

  btc_wallet_resend(wallet);

  return 1;
fail:
  btc_wallet_unload_database(wallet);
  btc_wclient_close(client);
  return 0;
}

void
btc_wallet_close(btc_wallet_t *wallet) {
  const btc_wclient_t *client = &wallet->client;

  btc_wallet_unload_filter(wallet);
  btc_wallet_unload_data(wallet);
  btc_wallet_unload_state(wallet);
  btc_wallet_unload_database(wallet);

  btc_wclient_close(client);
}

static int
btc_wallet_account(btc_account_t *acct,
                   btc_wallet_t *wallet,
                   uint32_t account) {
  if (account == BTC_NO_ACCOUNT)
    account = 0;

  btc_account_init(acct, (btc_bloom_t *)&wallet->filter);

  return db_get_account(wallet->db, account, acct);
}

static void
btc_wallet_sync(btc_wallet_t *wallet, const btc_tx_t *tx) {
  ldb_batch_t batch;
  btc_intmap_t map;
  btc_mapiter_t it;
  int exists;
  size_t i;

  btc_intmap_init(&map);

  for (i = 0; i < tx->outputs.length; i++) {
    const btc_output_t *output = tx->outputs.items[i];
    btc_path_t path, *state;

    if (!btc_wallet_output_path(&path, wallet, output))
      continue;

    it = btc_intmap_insert(&map, path.account, &exists);

    if (!exists)
      map.vals[it] = btc_path_create();

    state = map.vals[it];

    if (path.change) {
      if (path.index > state->change)
        state->change = path.index;
    } else {
      if (path.index > state->index)
        state->index = path.index;
    }
  }

  db_batch(&batch);

  btc_map_each(&map, it) {
    uint32_t account = map.keys[it];
    btc_path_t *state = map.vals[it];
    btc_account_t acct;

    CHECK(btc_wallet_account(&acct, wallet, account));

    btc_account_sync(&acct, &batch, state->index, state->change);

    btc_path_destroy(state);
  }

  db_write(wallet->db, &batch);

  btc_intmap_clear(&map);
}

int32_t
btc_wallet_height(btc_wallet_t *wallet) {
  return wallet->state.height;
}

int64_t
btc_wallet_rate(btc_wallet_t *wallet, int64_t rate) {
  if (rate == 0)
    rate = 10000;

  if (rate >= 0)
    wallet->rate = rate;

  return wallet->rate;
}

void
btc_wallet_tick(void *ptr) {
  btc_wallet_t *wallet = ptr;
  btc_master_maybe_lock(&wallet->master);
}

int
btc_wallet_locked(btc_wallet_t *wallet) {
  return wallet->master.locked;
}

int
btc_wallet_encrypted(btc_wallet_t *wallet) {
  return wallet->master.algorithm != BTC_KDF_NONE;
}

int64_t
btc_wallet_until(btc_wallet_t *wallet) {
  return wallet->master.deadline;
}

void
btc_wallet_lock(btc_wallet_t *wallet) {
  btc_master_lock(&wallet->master);
}

int
btc_wallet_unlock(btc_wallet_t *wallet, const char *pass, int64_t msec) {
  return btc_master_unlock(&wallet->master, pass, msec);
}

int
btc_wallet_encrypt(btc_wallet_t *wallet, const char *pass) {
  ldb_batch_t batch;

  if (!btc_master_encrypt(&wallet->master, BTC_KDF_PBKDF2, pass))
    return 0;

  db_batch(&batch);

  db_put_master(&batch, &wallet->master);

  db_write(wallet->db, &batch);

  ldb_compact(wallet->db, 0, 0);

  return 1;
}

int
btc_wallet_decrypt(btc_wallet_t *wallet) {
  ldb_batch_t batch;

  if (wallet->master.algorithm == BTC_KDF_NONE)
    return 1;

  if (!btc_master_encrypt(&wallet->master, BTC_KDF_NONE, NULL))
    return 0;

  db_batch(&batch);

  db_put_master(&batch, &wallet->master);

  db_write(wallet->db, &batch);

  return 1;
}

int
btc_wallet_master(btc_mnemonic_t *mnemonic,
                  btc_hdnode_t *master,
                  btc_wallet_t *wallet) {
  if (wallet->master.locked)
    return 0;

  *mnemonic = wallet->master.mnemonic;
  *master = wallet->master.chain;

  return 1;
}

int
btc_wallet_purpose(uint32_t *purpose,
                   uint32_t *account,
                   btc_wallet_t *wallet,
                   uint32_t number) {
  btc_account_t acct;

  if (BTC_WATCH_ONLY(number)) {
    if (!btc_wallet_account(&acct, wallet, number))
      return 0;

    *purpose = btc_bip32_purpose[acct.key.type];
    *account = acct.key.index & ~BTC_BIP32_HARDEN;

    return 1;
  }

  *purpose = btc_bip32_purpose[wallet->master.type];
  *account = number;

  return 1;
}

int
btc_wallet_path(btc_path_t *path,
                btc_wallet_t *wallet,
                const btc_address_t *addr) {
  if (!btc_bloom_has(&wallet->filter, addr->hash, addr->length))
    return 0;

  return db_get_path(wallet->db, addr, path);
}

int
btc_wallet_output_path(btc_path_t *path,
                       btc_wallet_t *wallet,
                       const btc_output_t *output) {
  btc_address_t addr;

  if (!btc_address_set_script(&addr, &output->script))
    return 0;

  return btc_wallet_path(path, wallet, &addr);
}

int
btc_wallet_lookup(uint32_t *account, btc_wallet_t *wallet, const char *name) {
  size_t len = strlen(name);

  if (len == 0 || len > 63)
    return 0;

  if (strcmp(name, "*") == 0 ||
      strcmp(name, ".") == 0) {
    return BTC_NO_ACCOUNT;
  }

  return db_get_index(wallet->db, name, account);
}

int
btc_wallet_name(char *name, size_t size,
                btc_wallet_t *wallet,
                uint32_t account) {
  if (account == BTC_NO_ACCOUNT)
    return btc_strcpy(name, size, "*");

  return db_get_name(wallet->db, account, name, size);
}

int
btc_wallet_balance(btc_balance_t *bal, btc_wallet_t *wallet, uint32_t account) {
  if (account == BTC_NO_ACCOUNT) {
    *bal = wallet->balance;
    return 1;
  }

  return db_get_balance(wallet->db, account, bal);
}

int
btc_wallet_watched(btc_balance_t *bal, btc_wallet_t *wallet, uint32_t account) {
  if (account == BTC_NO_ACCOUNT) {
    *bal = wallet->watched;
    return 1;
  }

  if ((account & BTC_BIP32_HARDEN) == 0) {
    btc_balance_init(bal);
    return 1;
  }

  return db_get_balance(wallet->db, account, bal);
}

int
btc_wallet_privkey(uint8_t *privkey,
                   btc_wallet_t *wallet,
                   const btc_path_t *path) {
  btc_hdnode_t node;

  if (wallet->master.locked)
    return 0;

  if (!btc_master_leaf(&node, &wallet->master, path))
    return 0;

  memcpy(privkey, node.seckey, 32);

  btc_hdpriv_clear(&node);

  return 1;
}

int
btc_wallet_pubkey(uint8_t *pubkey,
                  btc_wallet_t *wallet,
                  const btc_path_t *path) {
  btc_account_t acct;
  btc_hdnode_t node;

  if (!btc_wallet_account(&acct, wallet, path->account))
    return 0;

  btc_account_leaf(&node, &acct, path->change, path->index);

  memcpy(pubkey, node.pubkey, 33);

  btc_hdpub_clear(&node);

  return 1;
}

int
btc_wallet_address(btc_address_t *addr,
                   btc_wallet_t *wallet,
                   const btc_path_t *path) {
  btc_account_t acct;

  if (!btc_wallet_account(&acct, wallet, path->account))
    return 0;

  btc_account_address(addr, &acct, path->change, path->index);

  return 1;
}

int
btc_wallet_receive(btc_address_t *addr,
                   btc_wallet_t *wallet,
                   uint32_t account) {
  btc_account_t acct;

  if (!btc_wallet_account(&acct, wallet, account))
    return 0;

  btc_account_receive(addr, &acct);

  return 1;
}

int
btc_wallet_change(btc_address_t *addr,
                  btc_wallet_t *wallet,
                  uint32_t account) {
  btc_account_t acct;

  if (!btc_wallet_account(&acct, wallet, account))
    return 0;

  btc_account_change(addr, &acct);

  return 1;
}

int
btc_wallet_next(btc_address_t *addr,
                btc_wallet_t *wallet,
                uint32_t account) {
  btc_account_t acct;
  ldb_batch_t batch;

  if (!btc_wallet_account(&acct, wallet, account))
    return 0;

  db_batch(&batch);

  btc_account_next(&acct, &batch);

  db_write(wallet->db, &batch);

  btc_account_receive(addr, &acct);

  return 1;
}

int
btc_wallet_prev(btc_address_t *addr,
                btc_wallet_t *wallet,
                uint32_t account) {
  btc_account_t acct;
  ldb_batch_t batch;

  if (!btc_wallet_account(&acct, wallet, account))
    return 0;

  db_batch(&batch);

  btc_account_prev(&acct, &batch);

  db_write(wallet->db, &batch);

  btc_account_receive(addr, &acct);

  return 1;
}

int
btc_wallet_create_account(btc_wallet_t *wallet,
                          const char *name,
                          uint32_t account) {
  size_t len = strlen(name);
  btc_account_t acct;
  ldb_batch_t batch;

  if (wallet->master.locked)
    return 0;

  if (len == 0 || len > 63 ||
      strcmp(name, "*") == 0 ||
      strcmp(name, ".") == 0) {
    return 0;
  }

  if (db_has_index(wallet->db, name))
    return 0;

  if (account == BTC_NO_ACCOUNT) {
    wallet->account_index++;

    while (db_has_account(wallet->db, wallet->account_index))
      wallet->account_index++;

    account = wallet->account_index;
  } else {
    if (db_has_account(wallet->db, account))
      return 0;
  }

  if (account & BTC_BIP32_HARDEN)
    return 0;

  db_batch(&batch);

  btc_account_init(&acct, &wallet->filter);
  btc_account_generate(&acct, &batch, name, &wallet->master, account);

  db_put_wallet(&batch, wallet);

  db_write(wallet->db, &batch);

  btc_log(wallet, LOG_INFO, "Created account %s (%u).", acct.name, acct.index);

  return 1;
}

int
btc_wallet_create_watcher(btc_wallet_t *wallet,
                          const char *name,
                          const btc_hdnode_t *node) {
  size_t len = strlen(name);
  btc_account_t acct;
  ldb_batch_t batch;

  if (len == 0 || len > 63 ||
      strcmp(name, "*") == 0 ||
      strcmp(name, ".") == 0) {
    return 0;
  }

  switch (node->type) {
    case BTC_BIP32_STANDARD:
    case BTC_BIP32_P2WPKH:
    case BTC_BIP32_NESTED_P2WPKH:
      break;
    default:
      return 0;
  }

  if (node->depth != 2 || !(node->index & BTC_BIP32_HARDEN))
    return 0;

  if (db_has_index(wallet->db, name))
    return 0;

  db_batch(&batch);

  btc_account_init(&acct, &wallet->filter);
  btc_account_watch(&acct, &batch, name, node, ++wallet->watch_index);

  db_put_wallet(&batch, wallet);

  db_write(wallet->db, &batch);

  return 1;
}

btc_outset_t *
btc_wallet_frozen(btc_wallet_t *wallet) {
  return &wallet->frozen;
}

void
btc_wallet_freeze(btc_wallet_t *wallet, const btc_outpoint_t *outpoint) {
  btc_outset_t *map = &wallet->frozen;
  btc_mapiter_t it;
  int exists;

  it = btc_outset_insert(map, outpoint, &exists);

  if (!exists)
    map->keys[it] = btc_outpoint_clone(outpoint);
}

void
btc_wallet_unfreeze(btc_wallet_t *wallet, const btc_outpoint_t *outpoint) {
  btc_outset_t *map = &wallet->frozen;
  btc_outpoint_t *key;
  btc_mapiter_t it;

  if (outpoint == NULL) {
    btc_map_each(map, it)
      btc_outpoint_destroy(map->keys[it]);

    btc_outset_reset(map);

    return;
  }

  key = btc_outset_del(map, outpoint);

  if (key != NULL)
    btc_outpoint_destroy(key);
}

int
btc_wallet_is_frozen(btc_wallet_t *wallet, const btc_outpoint_t *outpoint) {
  return btc_outset_has(&wallet->frozen, outpoint);
}

void
btc_wallet_freezes(btc_wallet_t *wallet, const btc_tx_t *tx) {
  size_t i;

  if (btc_tx_is_coinbase(tx))
    return;

  for (i = 0; i < tx->inputs.length; i++) {
    const btc_input_t *input = tx->inputs.items[i];

    btc_wallet_freeze(wallet, &input->prevout);
  }
}

void
btc_wallet_unfreezes(btc_wallet_t *wallet, const btc_tx_t *tx) {
  size_t i;

  if (btc_tx_is_coinbase(tx))
    return;

  for (i = 0; i < tx->inputs.length; i++) {
    const btc_input_t *input = tx->inputs.items[i];

    btc_wallet_unfreeze(wallet, &input->prevout);
  }
}

int
btc_wallet_fund(btc_wallet_t *wallet,
                uint32_t account,
                const btc_selopt_t *options,
                btc_tx_t *tx) {
  btc_coiniter_t *it;
  btc_selector_t sel;
  btc_address_t addr;
  btc_selopt_t opt;
  int ret = 0;

  if (tx->outputs.length == 0)
    return 0;

  if (options == NULL)
    btc_selopt_init(&opt);
  else
    opt = *options;

  opt.height = wallet->state.height;
  opt.rate = wallet->rate;

  if (account != BTC_NO_ACCOUNT)
    opt.watch = 1;

  btc_selector_init(&sel, &opt, tx);

  it = btc_wallet_coins(wallet);

  btc_coiniter_account(it, account);

  btc_coiniter_each(it) {
    btc_outpoint_t *prevout = btc_coiniter_key(it);
    btc_coin_t *coin;

    if (btc_wallet_is_frozen(wallet, prevout))
      continue;

    coin = btc_coiniter_value(it);

    btc_selector_push(&sel, prevout, coin);
  }

  if (!btc_wallet_change(&addr, wallet, account))
    goto fail;

  if (!btc_selector_fill(&sel, &addr))
    goto fail;

  ret = 1;
fail:
  btc_coiniter_destroy(it);
  btc_selector_clear(&sel);
  return ret;
}

static int
derive(uint8_t *priv, const btc_address_t *addr, void *arg) {
  btc_wallet_t *wallet = arg;
  btc_path_t path;

  if (!btc_wallet_path(&path, wallet, addr))
    return 0;

  return btc_wallet_privkey(priv, wallet, &path);
}

int
btc_wallet_sign(btc_wallet_t *wallet, btc_tx_t *tx, const btc_view_t *view) {
  if (wallet->master.locked)
    return 0;

  return btc_tx_sign(tx, view, derive, wallet);
}

int
btc_wallet_send(btc_wallet_t *wallet,
                uint32_t account,
                const btc_selopt_t *options,
                btc_tx_t *tx) {
  const btc_wclient_t *client = &wallet->client;
  unsigned int flags = BTC_SCRIPT_STANDARD_VERIFY_FLAGS;
  int32_t height = wallet->state.height + 1;
  btc_view_t *view;
  size_t i, total;

  if (wallet->master.locked)
    return 0;

  for (i = 0; i < tx->outputs.length; i++) {
    const btc_output_t *output = tx->outputs.items[i];

    if (btc_output_is_dust(output, BTC_MIN_RELAY))
      return 0;
  }

  if (!btc_wallet_fund(wallet, account, options, tx))
    return 0;

  view = btc_wallet_view(wallet, tx);

  btc_tx_sort(tx);

  /* Consensus sanity checks. */
  if (!btc_tx_check_sanity(0, tx) ||
      !btc_tx_check_inputs(0, tx, view, height)) {
    btc_view_destroy(view);
    return 0;
  }

  total = btc_wallet_sign(wallet, tx, view);

  if (total != tx->inputs.length) {
    btc_view_destroy(view);
    return 0;
  }

  btc_tx_refresh(tx);

  /* Policy sanity checks. */
  if (btc_tx_weight(tx) > BTC_MAX_TX_WEIGHT ||
      btc_tx_sigops_cost(tx, view, flags) > BTC_MAX_TX_SIGOPS_COST ||
      btc_tx_verify(tx, view, flags) == 0) {
    btc_view_destroy(view);
    return 0;
  }

  btc_view_destroy(view);

  CHECK(btc_wallet_add_tx(wallet, tx));

  btc_log(wallet, LOG_INFO, "Sending transaction %H.", tx->hash);

  btc_wclient_send(client, tx);

  return 1;
}

static void
btc_wallet_set_tip(btc_wallet_t *wallet, const btc_entry_t *tip) {
  int32_t keep = wallet->network->block.keep_blocks;
  btc_state_t *state = &wallet->state;
  ldb_batch_t batch;

  db_batch(&batch);

  if (tip->height < state->height) {
    /* Hashes ahead of our new tip that we need to delete. */
    while (state->height != tip->height) {
      db_del_block(&batch, state->height);
      state->height -= 1;
    }
  } else if (tip->height > state->height) {
    ASSERT(tip->height == state->height + 1);
    state->height += 1;
  }

  if (tip->height < state->start_height) {
    state->start_height = tip->height;
    btc_hash_copy(state->start_hash, tip->hash);
    state->marked = 0;
  }

  if (tip->height >= keep)
    db_del_block(&batch, tip->height - keep);

  /* Save tip and state. */
  db_put_block(&batch, tip->height, tip->hash);
  db_put_state(&batch, state);
  db_write(wallet->db, &batch);
}

static void
btc_wallet_mark_state(btc_wallet_t *wallet, const btc_entry_t *entry) {
  btc_state_t *state = &wallet->state;
  ldb_batch_t batch;

  state->marked = 1;
  state->start_height = entry->height;

  btc_hash_copy(state->start_hash, entry->hash);

  db_batch(&batch);
  db_put_state(&batch, state);
  db_write(wallet->db, &batch);
}

static int
btc_wallet_insert(btc_wallet_t *wallet,
                  const btc_tx_t *tx,
                  const btc_entry_t *entry,
                  int32_t index) {
  if (!btc_txdb_add(wallet, tx, entry, index))
    return 0;

  if (entry != NULL && !wallet->state.marked)
    btc_wallet_mark_state(wallet, entry);

  btc_wallet_sync(wallet, tx);

  btc_log(wallet, LOG_INFO, "Added transaction %H.", tx->hash);

  return 1;
}

static int
btc_wallet_connect(btc_wallet_t *wallet,
                   const btc_entry_t *entry,
                   const btc_block_t *block) {
  int total = 0;
  size_t i;

  btc_wallet_set_tip(wallet, entry);

  for (i = 0; i < block->txs.length; i++) {
    const btc_tx_t *tx = block->txs.items[i];

    total += btc_wallet_insert(wallet, tx, entry, i);
  }

  if (total > 0) {
    btc_log(wallet, LOG_INFO, "Connected block %H (tx=%d).",
                              entry->hash, total);
  }

  return total;
}

int
btc_wallet_add_tx(btc_wallet_t *wallet, const btc_tx_t *tx) {
  return btc_wallet_insert(wallet, tx, NULL, -1);
}

int
btc_wallet_add_block(btc_wallet_t *wallet,
                     const btc_entry_t *entry,
                     const btc_block_t *block) {
  const btc_state_t *state = &wallet->state;

  if (entry->height < state->height) {
    btc_log(wallet, LOG_WARN, "Connecting low blocks (%d).", entry->height);
    return 0;
  }

  if (entry->height == state->height) {
    /* We let blocks of the same height
       through specifically for rescans:
       we always want to rescan the last
       block since the state may have
       updated before the block was fully
       processed (in the case of a crash). */
    btc_log(wallet, LOG_WARN, "Already saw block (%d).", entry->height);
  } else if (entry->height != state->height + 1) {
    btc_wallet_rescan(wallet, state->height);
    return 0;
  }

  if (wallet->options.checkpoints && !state->marked) {
    if (entry->height <= wallet->network->last_checkpoint) {
      btc_wallet_set_tip(wallet, entry);
      return 0;
    }
  }

  return btc_wallet_connect(wallet, entry, block);
}

int
btc_wallet_remove_block(btc_wallet_t *wallet, const btc_entry_t *entry) {
  const btc_state_t *state = &wallet->state;
  btc_entry_t prev;
  int total;

  if (entry->height == 0) {
    btc_log(wallet, LOG_ERROR, "Bad disconnection (genesis block).");
    return 0;
  }

  if (entry->height > state->height) {
    btc_log(wallet, LOG_WARN, "Disconnecting high blocks (%d).", entry->height);
    return 0;
  }

  if (entry->height != state->height) {
    btc_log(wallet, LOG_ERROR, "Bad disconnection (height mismatch).");
    return 0;
  }

  total = btc_txdb_revert(wallet, entry->height);

  btc_hash_copy(prev.hash, entry->header.prev_block);

  prev.height = entry->height - 1;

  btc_wallet_set_tip(wallet, &prev);

  btc_log(wallet, LOG_WARN, "Disconnected block %H (tx=%d).",
                            entry->hash, total);

  return 1;
}

int
btc_wallet_rollback(btc_wallet_t *wallet, int32_t height) {
  btc_entry_t tip;
  int total;

  if (height > wallet->state.height) {
    btc_log(wallet, LOG_ERROR, "Cannot rollback to the future.");
    return 0;
  }

  if (height == wallet->state.height) {
    btc_log(wallet, LOG_INFO, "Rolled back to same height (%d).",
                              height);
    return 1;
  }

  btc_log(wallet, LOG_INFO, "Rolling back %d blocks to height %d.",
                            wallet->state.height - height, height);

  tip.height = height;

  if (!db_get_block(wallet->db, height, tip.hash))
    return 0;

  total = btc_txdb_revert(wallet, height + 1);

  btc_wallet_set_tip(wallet, &tip);

  btc_log(wallet, LOG_INFO, "Rolled back %d transactions.", total);

  return 1;
}

int
btc_wallet_rescan(btc_wallet_t *wallet, int32_t height) {
  const btc_wclient_t *client = &wallet->client;
  const btc_entry_t *entry;

  if (!wallet->options.client)
    return 0;

  if (height < 0)
    height = wallet->state.start_height;

  btc_log(wallet, LOG_INFO, "Scanning %d blocks.",
                            wallet->state.height - height + 1);

  if (!btc_wallet_rollback(wallet, height))
    return 0;

  entry = btc_wclient_by_height(client, height);

  while (entry != NULL) {
    btc_block_t *block = btc_wclient_get_block(client, entry);

    if (block == NULL)
      return 0;

    btc_log(wallet, LOG_INFO, "Scanning block %H (%d).",
                              entry->hash, entry->height);

    btc_wallet_connect(wallet, entry, block);

    btc_block_destroy(block);

    entry = btc_wclient_by_height(client, entry->height + 1);
  }

  return 1;
}

int
btc_wallet_abandon(btc_wallet_t *wallet, const uint8_t *hash) {
  return btc_txdb_abandon(wallet, hash);
}

int
btc_wallet_backup(btc_wallet_t *wallet, const char *path) {
  return ldb_backup(wallet->db, path) == LDB_OK;
}

int
btc_wallet_coin(btc_coin_t **coin,
                btc_wallet_t *wallet,
                const uint8_t *hash,
                uint32_t index) {
  return db_get_coin(wallet->db, hash, index, coin);
}

int
btc_wallet_meta(btc_txmeta_t *meta, btc_wallet_t *wallet, const uint8_t *hash) {
  return db_get_txmeta(wallet->db, hash, meta);
}

int
btc_wallet_tx(btc_tx_t **tx, btc_wallet_t *wallet, const uint8_t *hash) {
  return db_get_tx(wallet->db, hash, tx);
}

btc_view_t *
btc_wallet_view(btc_wallet_t *wallet, const btc_tx_t *tx) {
  btc_view_t *view = btc_view_create();
  btc_txdb_fill(wallet, view, tx);
  return view;
}

btc_view_t *
btc_wallet_undo(btc_wallet_t *wallet, const btc_tx_t *tx) {
  return btc_txdb_undo(wallet, tx);
}

btc_acctiter_t *
btc_wallet_accounts(btc_wallet_t *wallet) {
  return btc_acctiter_create(wallet->db);
}

btc_addriter_t *
btc_wallet_addresses(btc_wallet_t *wallet) {
  return btc_addriter_create(wallet->db);
}

btc_coiniter_t *
btc_wallet_coins(btc_wallet_t *wallet) {
  return btc_coiniter_create(wallet->db);
}

btc_txiter_t *
btc_wallet_txs(btc_wallet_t *wallet) {
  return btc_txiter_create(wallet->db);
}

void
btc_wallet_watch(btc_wallet_t *wallet, const uint8_t *hash, uint32_t index) {
  uint8_t raw[36];

  btc_raw_write(raw, hash, 32);
  btc_uint32_write(raw + 32, index);

  btc_bloom_add(&wallet->filter, raw, 36);
}

size_t
btc_wallet_size(const btc_wallet_t *wallet) {
  return 16 + btc_balance_size(&wallet->balance)
            + btc_balance_size(&wallet->watched);
}

uint8_t *
btc_wallet_write(uint8_t *zp, const btc_wallet_t *x) {
  zp = btc_uint32_write(zp, x->account_index);
  zp = btc_uint32_write(zp, x->watch_index);
  zp = btc_uint64_write(zp, x->unique_id);
  zp = btc_balance_write(zp, &x->balance);
  zp = btc_balance_write(zp, &x->watched);
  return zp;
}

int
btc_wallet_read(btc_wallet_t *z, const uint8_t **xp, size_t *xn) {
  if (!btc_uint32_read(&z->account_index, xp, xn))
    return 0;

  if (!btc_uint32_read(&z->watch_index, xp, xn))
    return 0;

  if (!btc_uint64_read(&z->unique_id, xp, xn))
    return 0;

  if (!btc_balance_read(&z->balance, xp, xn))
    return 0;

  if (!btc_balance_read(&z->watched, xp, xn))
    return 0;

  return 1;
}

size_t
btc_wallet_export(uint8_t *zp, const btc_wallet_t *x) {
  return btc_wallet_write(zp, x) - zp;
}

int
btc_wallet_import(btc_wallet_t *z, const uint8_t *xp, size_t xn) {
  return btc_wallet_read(z, &xp, &xn);
}
