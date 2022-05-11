/*!
 * txdb.c - wallet txdb for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <mako/address.h>
#include <mako/bip32.h>
#include <mako/bloom.h>
#include <mako/coins.h>
#include <mako/map.h>
#include <mako/script.h>
#include <mako/tx.h>
#include <mako/util.h>
#include <mako/vector.h>

#include "../internal.h"

#include "database.h"
#include "record.h"
#include "txdb.h"
#include "wallet.h"

/*
 * TXDB
 */

static int
btc_txdb_insert(btc_txdb_t *txdb,
                const btc_tx_t *tx,
                const btc_entry_t *entry,
                int32_t index) {
  int32_t height = entry ? entry->height : -1;
  uint64_t id = txdb->unique_id;
  ldb_t *db = txdb->db;
  btc_outpoint_t spend;
  btc_txmeta_t meta;
  btc_delta_t state;
  btc_mapiter_t it;
  ldb_batch_t b;
  int own = 0;
  size_t i;

  btc_txmeta_set(&meta, id, entry, index);

  btc_delta_init(&state);

  db_batch(&b);

  if (!btc_tx_is_coinbase(tx)) {
    /* We need to potentially spend some coins here. */
    for (i = 0; i < tx->inputs.length; i++) {
      const btc_input_t *input = tx->inputs.items[i];
      const btc_outpoint_t *op = &input->prevout;
      btc_coin_t *coin;
      btc_path_t path;

      btc_outpoint_set(&spend, tx->hash, i);

      if (!db_get_coin(db, op->hash, op->index, &coin)) {
        /* Watch all inputs for incoming txs. */
        /* This allows us to check for double spends. */
        if (!entry) {
          db_put_spend(&b, op->hash, op->index, &spend);
          btc_wallet_watch(txdb, op->hash, op->index);
        }
        continue;
      }

      CHECK(btc_wallet_output_path(&path, txdb, &coin->output));

      /* Write an undo coin for the credit
         and add it to the stxo set. */
      db_put_spend(&b, op->hash, op->index, &spend);
      db_put_undo(&b, tx->hash, i, coin);

      /* Unconfirmed balance should always
         be updated as it reflects the on-chain
         balance _and_ mempool balance assuming
         everything in the mempool were to confirm. */
      btc_delta_tx(&state, &path, 1);
      btc_delta_coin(&state, &path, -1);
      btc_delta_unconf(&state, &path, -coin->output.value);

      meta.resolved += 1;
      meta.inpval += coin->output.value;

      if (!entry) {
        /* If the tx is not mined, we do not
           disconnect the coin, we simply mark
           a `spent` flag on the credit. This
           effectively prevents the mempool
           from altering our utxo state
           permanently. It also makes it
           possible to compare the on-chain
           state vs. the mempool state. */
        coin->spent = 1;

        db_put_coin(&b, op->hash, op->index, coin);
      } else {
        /* If the tx is mined, we can safely
           remove the coin being spent. This
           coin will be indexed as an undo
           coin so it can be reconnected
           later during a reorg. */
        btc_delta_conf(&state, &path, -coin->output.value);

        db_del_coin(&b, op->hash, op->index);
        db_del_acoin(&b, path.account, op->hash, op->index);
      }

      btc_coin_destroy(coin);

      own = 1;
    }
  }

  /* Potentially add coins to the utxo set. */
  for (i = 0; i < tx->outputs.length; i++) {
    const btc_output_t *output = tx->outputs.items[i];
    btc_coin_t *coin;
    btc_path_t path;

    if (!btc_wallet_output_path(&path, txdb, output))
      continue;

    coin = btc_tx_coin(tx, i, height);
    coin->safe = own;
    coin->watch = (path.account & BTC_BIP32_HARDEN) != 0;

    btc_delta_tx(&state, &path, 1);
    btc_delta_coin(&state, &path, 1);
    btc_delta_unconf(&state, &path, output->value);

    if (entry)
      btc_delta_conf(&state, &path, output->value);

    db_put_coin(&b, tx->hash, i, coin);
    db_put_acoin(&b, path.account, tx->hash, i);

    btc_wallet_watch(txdb, tx->hash, i);

    btc_coin_destroy(coin);
  }

  /* If this didn't update any coins, it's not our transaction. */
  if (!state.updated) {
    btc_delta_clear(&state);
    db_clear(&b);
    return 0;
  }

  /* Save and index the transaction record. */
  db_put_txmeta(&b, tx->hash, &meta);
  db_put_tx(&b, tx->hash, tx);
  db_put_txid(&b, id, tx->hash);
  db_put_height(&b, height, id, tx->hash);

  /* Do some secondary indexing for account-based
     queries. This saves us a lot of time for
     queries later. */
  btc_map_each(&state.map, it) {
    uint32_t account = state.map.keys[it];
    btc_balance_t *delta = state.map.vals[it];

    db_update_balance(db, &b, account, delta);

    db_put_atxid(&b, account, id, tx->hash);
    db_put_aheight(&b, account, height, id, tx->hash);
  }

  /* Update block record. */
  if (entry) {
    db_put_blkmeta(&b, entry->height,
                       entry->hash,
                       entry->header.time);
    db_put_blkidx(&b, entry->height, index, tx->hash);
  }

  /* Commit the new state. */
  txdb->unique_id++;

  btc_balance_apply(&txdb->balance, &state.balance);
  btc_balance_apply(&txdb->watched, &state.watched);

  db_put_wallet(&b, txdb);
  db_write(db, &b);

  /* This transaction may unlock some coins now that we've seen it. */
  btc_wallet_unfreezes(txdb, tx);

  btc_delta_clear(&state);

  return 1;
}

static int
btc_txdb_confirm(btc_txdb_t *txdb,
                 const btc_tx_t *tx,
                 const btc_entry_t *entry,
                 int32_t index) {
  int32_t height = entry->height;
  ldb_t *db = txdb->db;
  btc_outpoint_t spend;
  btc_txmeta_t meta;
  btc_delta_t state;
  btc_mapiter_t it;
  ldb_batch_t b;
  int own = 0;
  size_t i;

  if (!db_get_txmeta(db, tx->hash, &meta))
    return 0;

  btc_txmeta_set_block(&meta, entry, index);

  btc_delta_init(&state);

  db_batch(&b);

  if (!btc_tx_is_coinbase(tx)) {
    /* Potentially spend coins. Now that the tx
       is mined, we can actually _remove_ coins
       from the utxo state. */
    for (i = 0; i < tx->inputs.length; i++) {
      const btc_input_t *input = tx->inputs.items[i];
      const btc_outpoint_t *op = &input->prevout;
      btc_coin_t *coin;
      int resolved = 0;
      btc_path_t path;

      /* There may be new credits available that we haven't seen yet. */
      if (!db_get_undo(db, tx->hash, i, &coin)) {
        if (!db_get_coin(db, op->hash, op->index, &coin)) {
          db_del_spend(&b, op->hash, op->index);
          continue;
        }

        /* Add a spend record and undo coin
           for the coin we now know is ours.
           We don't need to remove the coin
           since it was never added in the
           first place. */
        btc_outpoint_set(&spend, tx->hash, i);
        db_put_spend(&b, op->hash, op->index, &spend);
        db_put_undo(&b, tx->hash, i, coin);

        meta.resolved += 1;
        meta.inpval += coin->output.value;

        resolved = 1;
      }

      CHECK(coin->height != -1);
      CHECK(btc_wallet_output_path(&path, txdb, &coin->output));

      if (resolved) {
        btc_delta_coin(&state, &path, -1);
        btc_delta_unconf(&state, &path, -coin->output.value);
      }

      /* We can now safely remove the credit
         entirely, now that we know it's also
         been removed on-chain. */
      btc_delta_conf(&state, &path, -coin->output.value);

      db_del_coin(&b, op->hash, op->index);
      db_del_acoin(&b, path.account, op->hash, op->index);

      btc_coin_destroy(coin);

      own = 1;
    }
  }

  /* Update credit heights, including undo coins. */
  for (i = 0; i < tx->outputs.length; i++) {
    const btc_output_t *output = tx->outputs.items[i];
    btc_coin_t *coin;
    btc_path_t path;

    if (!btc_wallet_output_path(&path, txdb, output))
      continue;

    if (!db_get_coin(db, tx->hash, i, &coin)) {
      /* This credit didn't belong to us the first time we
         saw the transaction (before confirmation or rescan). */
      coin = btc_tx_coin(tx, i, height);
      coin->safe = own;
      coin->watch = (path.account & BTC_BIP32_HARDEN) != 0;

      btc_delta_coin(&state, &path, 1);
      btc_delta_unconf(&state, &path, coin->output.value);

      db_put_acoin(&b, path.account, tx->hash, i);

      btc_wallet_watch(txdb, tx->hash, i);
    }

    /* Credits spent in the mempool add an
       undo coin for ease. If this credit is
       spent in the mempool, we need to
       update the undo coin's height. */
    if (coin->spent)
      db_update_undo(db, &b, tx->hash, i, height);

    /* Update coin height and confirmed
       balance. Save once again. */
    btc_delta_conf(&state, &path, output->value);

    coin->height = height;

    db_put_coin(&b, tx->hash, i, coin);

    btc_coin_destroy(coin);
  }

  /* Save the new serialized transaction as
     the block-related properties have been
     updated. Also reindex for height. */
  db_put_txmeta(&b, tx->hash, &meta);
  db_del_height(&b, -1, meta.id);
  db_put_height(&b, height, meta.id, tx->hash);

  /* Secondary indexing also needs to change. */
  btc_map_each(&state.map, it) {
    uint32_t account = state.map.keys[it];
    btc_balance_t *delta = state.map.vals[it];

    db_update_balance(db, &b, account, delta);

    db_del_aheight(&b, account, -1, meta.id);
    db_put_aheight(&b, account, height, meta.id, tx->hash);
  }

  /* Update block record. */
  db_put_blkmeta(&b, entry->height,
                     entry->hash,
                     entry->header.time);
  db_put_blkidx(&b, entry->height, index, tx->hash);

  /* Commit the new state. The balance has updated. */
  btc_balance_apply(&txdb->balance, &state.balance);
  btc_balance_apply(&txdb->watched, &state.watched);

  db_put_wallet(&b, txdb);
  db_write(db, &b);

  /* This transaction may unlock some coins now that we've seen it. */
  btc_wallet_unfreezes(txdb, tx);

  btc_delta_clear(&state);

  return 1;
}

static int
btc_txdb_unconfirm(btc_txdb_t *txdb, const btc_tx_t *tx) {
  ldb_t *db = txdb->db;
  int32_t height, index;
  btc_outpoint_t spend;
  btc_txmeta_t meta;
  btc_delta_t state;
  btc_mapiter_t it;
  ldb_batch_t b;
  size_t i;

  if (!db_get_txmeta(db, tx->hash, &meta))
    return 0;

  CHECK(meta.height >= 0);
  CHECK(meta.index >= 0);

  height = meta.height;
  index = meta.index;

  btc_txmeta_set_block(&meta, NULL, -1);

  btc_delta_init(&state);

  db_batch(&b);

  if (!btc_tx_is_coinbase(tx)) {
    /* We need to reconnect the coins. Start
       by getting all of the undo coins we know
       about. */
    for (i = 0; i < tx->inputs.length; i++) {
      const btc_input_t *input = tx->inputs.items[i];
      const btc_outpoint_t *op = &input->prevout;
      btc_coin_t *coin;
      btc_path_t path;

      if (!db_get_undo(db, tx->hash, i, &coin)) {
        btc_outpoint_set(&spend, tx->hash, i);
        db_put_spend(&b, op->hash, op->index, &spend);
        btc_wallet_watch(txdb, op->hash, op->index);
        continue;
      }

      CHECK(coin->height != -1);
      CHECK(btc_wallet_output_path(&path, txdb, &coin->output));

      btc_delta_conf(&state, &path, coin->output.value);

      /* Resave the credit and mark it as spent in the mempool instead. */
      coin->spent = 1;
      coin->watch = (path.account & BTC_BIP32_HARDEN) != 0;

      db_put_coin(&b, op->hash, op->index, coin);
      db_put_acoin(&b, path.account, op->hash, op->index);

      btc_wallet_watch(txdb, op->hash, op->index);

      btc_coin_destroy(coin);
    }
  }

  /* We need to remove heights on the credits and undo coins. */
  for (i = 0; i < tx->outputs.length; i++) {
    const btc_output_t *output = tx->outputs.items[i];
    btc_coin_t *coin;
    btc_path_t path;

    if (!btc_wallet_output_path(&path, txdb, output))
      continue;

    /* Potentially update undo coin height. */
    CHECK(db_get_coin(db, tx->hash, i, &coin));

    if (coin->spent)
      db_update_undo(db, &b, tx->hash, i, -1);

    /* Update coin height and confirmed balance. Save once again. */
    btc_delta_conf(&state, &path, -output->value);

    coin->height = -1;

    db_put_coin(&b, tx->hash, i, coin);

    btc_coin_destroy(coin);
  }

  /* We need to update the now-removed
     block properties and reindex due
     to the height change. */
  db_put_txmeta(&b, tx->hash, &meta);
  db_del_height(&b, height, meta.id);
  db_put_height(&b, -1, meta.id, tx->hash);

  /* Secondary indexing also needs to change. */
  btc_map_each(&state.map, it) {
    uint32_t account = state.map.keys[it];
    btc_balance_t *delta = state.map.vals[it];

    db_update_balance(db, &b, account, delta);

    db_del_aheight(&b, account, height, meta.id);
    db_put_aheight(&b, account, -1, meta.id, tx->hash);
  }

  db_del_blkmeta(&b, height);
  db_del_blkidx(&b, height, index);

  /* Commit state due to unconfirmed vs. confirmed balance change. */
  btc_balance_apply(&txdb->balance, &state.balance);
  btc_balance_apply(&txdb->watched, &state.watched);

  db_put_wallet(&b, txdb);
  db_write(db, &b);

  btc_delta_clear(&state);

  return 1;
}

static int
btc_txdb_erase(btc_txdb_t *txdb, const btc_tx_t *tx) {
  ldb_t *db = txdb->db;
  btc_txmeta_t meta;
  btc_delta_t state;
  btc_mapiter_t it;
  ldb_batch_t b;
  size_t i;

  if (!db_get_txmeta(db, tx->hash, &meta))
    return 0;

  btc_delta_init(&state);

  db_batch(&b);

  if (!btc_tx_is_coinbase(tx)) {
    /* We need to undo every part of the
       state this transaction ever touched.
       Start by getting the undo coins. */
    for (i = 0; i < tx->inputs.length; i++) {
      const btc_input_t *input = tx->inputs.items[i];
      const btc_outpoint_t *op = &input->prevout;
      btc_coin_t *coin;
      btc_path_t path;

      if (!db_get_undo(db, tx->hash, i, &coin)) {
        if (meta.height < 0)
          db_del_spend(&b, op->hash, op->index);
        continue;
      }

      CHECK(btc_wallet_output_path(&path, txdb, &coin->output));

      /* Recalculate the balance, remove
         from stxo set, remove the undo
         coin, and resave the credit. */
      btc_delta_tx(&state, &path, -1);
      btc_delta_coin(&state, &path, 1);
      btc_delta_unconf(&state, &path, coin->output.value);

      if (meta.height >= 0)
        btc_delta_conf(&state, &path, coin->output.value);

      db_del_spend(&b, op->hash, op->index);
      db_del_undo(&b, tx->hash, i);

      coin->spent = 0;
      coin->watch = (path.account & BTC_BIP32_HARDEN) != 0;

      db_put_coin(&b, op->hash, op->index, coin);
      db_put_acoin(&b, path.account, op->hash, op->index);

      btc_wallet_watch(txdb, op->hash, op->index);

      btc_coin_destroy(coin);
    }
  }

  /* We need to remove all credits this transaction created. */
  for (i = 0; i < tx->outputs.length; i++) {
    const btc_output_t *output = tx->outputs.items[i];
    btc_path_t path;

    if (!btc_wallet_output_path(&path, txdb, output))
      continue;

    btc_delta_tx(&state, &path, -1);
    btc_delta_coin(&state, &path, -1);
    btc_delta_unconf(&state, &path, -output->value);

    if (meta.height >= 0)
      btc_delta_conf(&state, &path, -output->value);

    db_del_coin(&b, tx->hash, i);
    db_del_acoin(&b, path.account, tx->hash, i);
  }

  /* Remove the transaction data and unindex. */
  db_del_txmeta(&b, tx->hash);
  db_del_tx(&b, tx->hash);
  db_del_txid(&b, meta.id);
  db_del_height(&b, meta.height, meta.id);

  /* Remove all secondary indexing. */
  btc_map_each(&state.map, it) {
    uint32_t account = state.map.keys[it];
    btc_balance_t *delta = state.map.vals[it];

    db_update_balance(db, &b, account, delta);

    db_del_atxid(&b, account, meta.id);
    db_del_aheight(&b, account, meta.height, meta.id);
  }

  /* Update block records. */
  if (meta.height >= 0) {
    /* db_del_blkmeta(&b, meta.height); */
    db_del_blkidx(&b, meta.height, meta.index);
  }

  /* Update the transaction counter and commit new state. */
  btc_balance_apply(&txdb->balance, &state.balance);
  btc_balance_apply(&txdb->watched, &state.watched);

  db_put_wallet(&b, txdb);
  db_write(db, &b);

  btc_delta_clear(&state);

  return 1;
}

static int
btc_txdb_delete(btc_txdb_t *txdb, const btc_tx_t *tx) {
  ldb_t *db = txdb->db;
  size_t i;

  /* Remove all of the spender's spenders first. */
  for (i = 0; i < tx->outputs.length; i++) {
    btc_outpoint_t spend;
    btc_tx_t *stx;

    if (!db_get_spend(db, tx->hash, i, &spend))
      continue;

    if (!db_get_tx(db, spend.hash, &stx))
      continue;

    btc_txdb_delete(txdb, stx);
    btc_tx_destroy(stx);
  }

  /* Remove the spender. */
  return btc_txdb_erase(txdb, tx);
}

static int
btc_txdb_disconnect(btc_txdb_t *txdb, const uint8_t *hash) {
  ldb_t *db = txdb->db;
  btc_tx_t *tx;
  int ret;

  if (!db_get_tx(db, hash, &tx))
    return 0;

  ret = btc_txdb_unconfirm(txdb, tx);

  btc_tx_destroy(tx);

  return ret;
}

static int
btc_txdb_remove_conflicts(btc_txdb_t *txdb,
                          const btc_tx_t *tx,
                          int unconf_only) {
  ldb_t *db = txdb->db;
  btc_vector_t spends;
  int ret = 0;
  size_t i;

  if (btc_tx_is_coinbase(tx))
    return 1;

  btc_vector_init(&spends);

  /* Gather all spent records first. */
  for (i = 0; i < tx->inputs.length; i++) {
    const btc_input_t *input = tx->inputs.items[i];
    const btc_outpoint_t *op = &input->prevout;
    btc_outpoint_t spend;
    btc_tx_t *spender;

    /* Is it already spent? */
    if (!db_get_spend(db, op->hash, op->index, &spend))
      continue;

    /* Did _we_ spend it? */
    if (btc_hash_equal(spend.hash, tx->hash))
      continue;

    if (unconf_only) {
      btc_txmeta_t meta;

      if (!db_get_txmeta(db, spend.hash, &meta))
        continue;

      if (meta.height >= 0)
        goto fail;
    }

    if (!db_get_tx(db, spend.hash, &spender))
      continue;

    btc_vector_push(&spends, spender);
  }

  /* Once we know we're not going to
     screw things up, remove the double
     spenders. */
  for (i = 0; i < spends.length; i++) {
    /* Remove the double spender. */
    btc_txdb_delete(txdb, spends.items[i]);
  }

  ret = 1;
fail:
  for (i = 0; i < spends.length; i++)
    btc_tx_destroy(spends.items[i]);

  btc_vector_clear(&spends);

  return ret;
}

static int
hash_from_script(const uint8_t **hash, const btc_script_t *script) {
  if (btc_script_get_p2wpkh(hash, script))
    return 1;

  if (btc_script_get_p2sh(hash, script))
    return 1;

  if (btc_script_get_p2pkh(hash, script))
    return 1;

  return 0;
}

static int
tx_is_ours(btc_txdb_t *txdb, const btc_tx_t *tx) {
  const uint8_t *hash;
  uint8_t raw[36];
  size_t i;

  for (i = 0; i < tx->outputs.length; i++) {
    const btc_output_t *output = tx->outputs.items[i];

    if (!hash_from_script(&hash, &output->script))
      continue;

    if (btc_bloom_has(&txdb->filter, hash, 20))
      return 1;
  }

  for (i = 0; i < tx->inputs.length; i++) {
    const btc_input_t *input = tx->inputs.items[i];

    btc_outpoint_write(raw, &input->prevout);

    if (btc_bloom_has(&txdb->filter, raw, 36))
      return 1;
  }

  return 0;
}

/*
 * API
 */

int
btc_txdb_add(btc_txdb_t *txdb,
             const btc_tx_t *tx,
             const btc_entry_t *entry,
             int32_t index) {
  ldb_t *db = txdb->db;
  btc_txmeta_t meta;

  if (!tx_is_ours(txdb, tx))
    return 0;

  if (db_get_txmeta(db, tx->hash, &meta)) {
    /* Existing tx is already confirmed. Ignore. */
    if (meta.height != -1)
      return 0;

    /* The incoming tx won't confirm the
       existing one anyway. Ignore. */
    if (!entry)
      return 0;

    /* Confirm transaction. */
    return btc_txdb_confirm(txdb, tx, entry, index);
  }

  if (!entry) {
    /* Potentially remove double-spenders. */
    /* Only remove if they're not confirmed. */
    if (!btc_txdb_remove_conflicts(txdb, tx, 1))
      return 0;
  } else {
    /* Potentially remove double-spenders. */
    btc_txdb_remove_conflicts(txdb, tx, 0);
  }

  /* Finally we can do a regular insertion. */
  return btc_txdb_insert(txdb, tx, entry, index);
}

int
btc_txdb_remove(btc_txdb_t *txdb, const uint8_t *hash) {
  ldb_t *db = txdb->db;
  btc_tx_t *tx;
  int ret;

  if (!db_get_tx(db, hash, &tx))
    return 0;

  ret = btc_txdb_delete(txdb, tx);

  btc_tx_destroy(tx);

  return ret;
}

int
btc_txdb_abandon(btc_txdb_t *txdb, const uint8_t *hash) {
  ldb_t *db = txdb->db;
  btc_txmeta_t meta;

  if (!db_get_txmeta(db, hash, &meta))
    return 0;

  if (meta.height >= 0)
    return 0;

  return btc_txdb_remove(txdb, hash);
}

int
btc_txdb_revert(btc_txdb_t *txdb, int32_t height) {
  /* Disconnect all blocks down to and including `height`. */
  ldb_readopt_t opt = *ldb_iteropt_default;
  uint8_t buf1[KEY_BLKIDX_LEN];
  uint8_t buf2[KEY_BLKIDX_LEN];
  ldb_t *db = txdb->db;
  ldb_slice_t min, max;
  ldb_iter_t *it;
  int total = 0;

  opt.snapshot = ldb_snapshot(db);

  it = ldb_iterator(db, &opt);
  min = key_blkidx(height, 0, buf1);
  max = key_blkidx(-1, -1, buf2);

  ldb_iter_reverse(it, &max, &min) {
    ldb_slice_t val = ldb_iter_val(it);

    if (val.size != 32)
      db_abort("txdb_revert", LDB_CORRUPTION);

    total += btc_txdb_disconnect(txdb, val.data);
  }

  ldb_iter_destroy(it);
  ldb_release(db, opt.snapshot);

  return total;
}

static btc_coin_t *
read_coin(const btc_outpoint_t *op, void *arg) {
  btc_coin_t *coin;
  ldb_t *db = arg;

  if (db_get_coin(db, op->hash, op->index, &coin))
    return coin;

  return NULL;
}

int
btc_txdb_fill(btc_txdb_t *txdb, btc_view_t *view, const btc_tx_t *tx) {
  return btc_view_fill(view, tx, read_coin, txdb->db);
}

btc_view_t *
btc_txdb_undo(btc_txdb_t *txdb, const btc_tx_t *tx) {
  ldb_iter_t *it = ldb_iterator(txdb->db, 0);
  btc_view_t *view = btc_view_create();
  uint8_t buf1[KEY_UNDO_LEN];
  uint8_t buf2[KEY_UNDO_LEN];
  ldb_slice_t min, max;

  min = key_undo(tx->hash, 0, buf1);
  max = key_undo(tx->hash, -1, buf2);

  ldb_iter_range(it, &min, &max) {
    ldb_slice_t key = ldb_iter_key(it);
    ldb_slice_t val = ldb_iter_val(it);
    const btc_input_t *input;
    uint8_t *kp = key.data;
    btc_coin_t *coin;
    uint32_t index;

    index = btc_read32be(kp + 33);

    if (index >= tx->inputs.length)
      break;

    input = tx->inputs.items[index];
    coin = btc_coin_decode(val.data, val.size);

    if (coin == NULL)
      db_abort("txdb_undo", LDB_CORRUPTION);

    btc_view_put(view, &input->prevout, coin);
  }

  ldb_iter_destroy(it);

  return view;
}
