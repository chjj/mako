#include <lmdb.h>
#include "../map.h"
#include "../impl.h"
#include "../internal.h"

KHASH_SET_INIT_CONST_HASH(hashes)

struct btc_chaindb_s {
  const btc_network_t *network;
  MDB_env *env;
  MDB_dbi db_meta;
  MDB_dbi db_coin;
  MDB_dbi db_index;
  MDB_dbi db_tip;
  khash_t(hashes) *hashes;
  btc_vector_t heights;
  btc_entry_t *head;
  btc_entry_t *tail;
  uint8_t *slab;
};

static void
btc_chaindb_init(struct btc_chaindb_s *db, const btc_network_t *network) {
  memset(db, 0, sizeof(*db));

  db->network = network;
  db->hashes = kh_init(hashes);

  btc_vector_init(&db->heights);

  CHECK(db->hash != NULL);

  db->slab = (uint8_t *)malloc(BTC_MAX_RAW_BLOCK_SIZE);

  CHECK(db->slab != NULL);
}

static void
btc_chaindb_clear(struct btc_chaindb_s *db) {
  kh_destroy(hashes, db->hashes);
  btc_vector_clear(&db->heights);
  free(db->slab);
  memset(db, 0, sizeof(*db));
}

struct btc_chaindb_s *
btc_chaindb_create(const btc_network_t *network) {
  struct btc_chaindb_s *db =
    (struct btc_chaindb_s *)malloc(sizeof(struct btc_chaindb_s));

  CHECK(db != NULL);

  btc_chaindb_init(db, network);

  return db;
}

void
btc_chaindb_destroy(struct btc_chaindb_s *db) {
  btc_chaindb_clear(db);
  free(db);
}

int
btc_chaindb_open(struct btc_chaindb_s *db, const char *path, size_t map_size) {
  int flags = MDB_NOTLS;
  MDB_txn *txn;
  int rc;

  rc = mdb_env_create(&db->env);

  if (rc != 0) {
    fprintf(stderr, "mdb_env_create: %s\n", mdb_strerror(rc));
    return 0;
  }

  rc = mdb_env_set_mapsize(db->env, map_size);

  if (rc != 0) {
    fprintf(stderr, "mdb_env_set_mapsize: %s\n", mdb_strerror(rc));
    mdb_env_close(db->env);
    return 0;
  }

  rc = mdb_env_set_maxdbs(db->env, 10);

  if (rc != 0) {
    fprintf(stderr, "mdb_env_set_maxdbs: %s\n", mdb_strerror(rc));
    mdb_env_close(db->env);
    return 0;
  }

  rc = mdb_env_open(db->env, path, flags, 0664);

  if (rc != 0) {
    fprintf(stderr, "mdb_env_open: %s\n", mdb_strerror(rc));
    mdb_env_close(db->env);
    return 0;
  }

  rc = mdb_txn_begin(db->env, NULL, 0, &txn);

  if (rc != 0) {
    fprintf(stderr, "mdb_txn_begin: %s\n", mdb_strerror(rc));
    mdb_env_close(db->env);
    return 0;
  }

  rc = mdb_dbi_open(txn, "meta", MDB_CREATE, &db->db_meta);

  if (rc != 0) {
    fprintf(stderr, "mdb_dbi_open: %s\n", mdb_strerror(rc));
    mdb_txn_abort(txn);
    mdb_env_close(db->env);
    return 0;
  }

  rc = mdb_dbi_open(txn, "coin", MDB_CREATE, &db->db_coin);

  if (rc != 0) {
    fprintf(stderr, "mdb_dbi_open: %s\n", mdb_strerror(rc));
    mdb_txn_abort(txn);
    mdb_env_close(db->env);
    return 0;
  }

  rc = mdb_dbi_open(txn, "index", MDB_CREATE, &db->db_index);

  if (rc != 0) {
    fprintf(stderr, "mdb_dbi_open: %s\n", mdb_strerror(rc));
    mdb_txn_abort(txn);
    mdb_env_close(db->env);
    return 0;
  }

  rc = mdb_dbi_open(txn, "tip", MDB_CREATE, &db->db_tip);

  if (rc != 0) {
    fprintf(stderr, "mdb_dbi_open: %s\n", mdb_strerror(rc));
    mdb_txn_abort(txn);
    mdb_env_close(db->env);
    return 0;
  }

  rc = mdb_txn_commit(txn);

  if (rc != 0) {
    fprintf(stderr, "mdb_txn_commit: %s\n", mdb_strerror(rc));
    mdb_env_close(db->env);
    return 0;
  }

  btc_chaindb_load(db);

  return 1;
}

void
btc_chaindb_close(struct btc_chaindb_s *db) {
  btc_chaindb_unload(db);

  mdb_dbi_close(db->env, db->db_meta);
  mdb_dbi_close(db->env, db->db_coin);
  mdb_dbi_close(db->env, db->db_index);
  mdb_dbi_close(db->env, db->db_tip);
  mdb_env_close(db->env);
}

static void
btc_chaindb_new(struct btc_chaindb_s *db) {
  btc_view_t *view = btc_view_create();
  btc_entry_t *entry = btc_entry_create();
  btc_block_t block;

  btc_block_init(&block);
  btc_block_import(&block, db->network.genesis.data,
                           db->network.genesis.length);

  btc_entry_set_block(entry, &block, NULL);

  CHECK(btc_chaindb_save(db, entry, &block, view));

  btc_block_clear(&block);
  btc_view_destroy(view);
}

static void
btc_chaindb_load(struct btc_chaindb_s *db) {
  static const uint8_t tip_key[1] = {'R'};
  btc_entry_t *entry, *tip;
  btc_entry_t *gen = NULL;
  uint8_t tip_hash[32];
  MDB_val mkey, mval;
  khiter_t it, iter;
  MDB_cursor *cur;
  MDB_txn *txn;
  int rc;

  CHECK(mdb_txn_begin(db->env, NULL, MDB_RDONLY, &txn) == 0);

  mkey.mv_data = (uint8_t *)tip_key;
  mkey.mv_size = 1;

  rc = mdb_get(txn, db->db_meta, &mkey, &mval);

  if (rc == MDB_NOTFOUND) {
    mdb_txn_abort(txn);
    btc_chaindb_new(db);
    return;
  }

  CHECK(rc == 0);
  CHECK(mval.mv_size >= 32);

  memcpy(tip_hash, mval.mv_data, 32);

  CHECK(mdb_cursor_open(txn, db->db_index, &cur) == 0);

  rc = mdb_cursor_get(cur, &mkey, &mval, MDB_FIRST);

  while (rc == 0) {
    entry = btc_entry_create();

    CHECK(btc_entry_import(entry, mval.mv_data, mval.mv_size));

    iter = kh_put(hashes, db->hashes, entry->hash, &rc);

    CHECK(rc > 0);

    kh_value(db->hashes, iter) = entry;

    rc = mdb_cursor_get(cur, &mkey, &mval, MDB_NEXT);
  }

  CHECK(rc == MDB_NOTFOUND);

  mdb_cursor_close(cur);
  mdb_txn_abort(txn);

  for (it = kh_begin(db->hashes); it != kh_end(db->hashes); it++) {
    if (!kh_exist(db->hashes, it))
      continue;

    entry = kh_value(db->hashes, it);

    if (entry->height == 0) {
      gen = entry;
      continue;
    }

    iter = kh_get(hashes, db->hashes, entry->header.prev_block);

    CHECK(iter != kh_end(db->hashes));

    entry->prev = kh_value(db->hashes, iter);
  }

  CHECK(gen != NULL);

  iter = kh_get(hashes, db->hashes, tip_hash);

  CHECK(iter != kh_end(db->hashes));

  tip = kh_value(db->hashes, iter);

  btc_vector_grow(&db->heights, (kh_size(db->hashes) * 3) / 2);
  btc_vector_resize(&db->heights, tip->height + 1);

  entry = tip;

  do {
    db->heights.items[entry->height] = entry;

    if (entry->prev != NULL)
      entry->prev->next = entry;

    entry = entry->prev;
  } while (entry != NULL);

  db->head = gen;
  db->tail = tip;
}

static void
btc_chaindb_unload(struct btc_chaindb_s *db) {
  btc_entry_t *entry;
  khiter_t it;

  for (it = kh_begin(db->hashes); it != kh_end(db->hashes); it++) {
    if (kh_exist(db->hashes, it))
      btc_entry_destroy(kh_value(db->hashes, it));
  }

  kh_clear(hashes, db->hashes);
  btc_vector_clear(&db->heights);

  db->gen = NULL;
  db->tip = NULL;
}

static btc_coin_t *
read_coin(void *ctx, void *arg, const btc_outpoint_t *prevout) {
  struct btc_chaindb_s *db = (struct btc_chaindb_s *)ctx;
  MDB_txn *txn = (MDB_txn *)arg;
  MDB_val mkey, mval;
  btc_coin_t *coin;
  uint8_t key[36];

  btc_outpoint_write(key, prevout);

  mkey.mv_data = key;
  mkey.mv_size = 36;

  rc = mdb_get(txn, db->db_coin, &mkey, &mval);

  if (rc != 0) {
    if (rc != MDB_NOTFOUND)
      fprintf(stderr, "mdb_get: %s\n", mdb_strerror(rc));

    return NULL;
  }

  coin = btc_coin_create();

  CHECK(btc_coin_import(coin, mval.mv_data, mval.mv_size));

  return coin;
}

int
btc_chaindb_spend(struct btc_chaindb_s *db,
                  btc_view_t *view,
                  const btc_tx_t *tx) {
  MDB_txn *txn;
  int rc;

  rc = mdb_txn_begin(db->env, NULL, MDB_RDONLY, &txn);

  if (rc != 0) {
    fprintf(stderr, "mdb_txn_begin: %s\n", mdb_strerror(rc));
    return 0;
  }

  rc = btc_view_spend(view, tx, read_coin, db, txn);

  mdb_txn_abort(txn);

  return rc;
}

static int
iterate_view(void *ctx,
             void *arg,
             const uint8_t *hash,
             uint32_t index,
             const btc_coin_t *coin) {
  struct btc_chaindb_s *db = (struct btc_chaindb_s *)ctx;
  MDB_txn *txn = (MDB_txn *)arg;
  uint8_t *val = db->slab; /* needs to be at least 1mb */
  MDB_val mkey, mval;
  uint8_t key[36];

  btc_raw_write(key, hash, 32);
  btc_uint32_write(key + 32, index);

  mkey.mv_data = key;
  mkey.mv_size = klen;

  if (coin->spent) {
    rc = mdb_del(txn, db->db_coin, &mkey, NULL);
  } else {
    mval.mv_data = val;
    mval.mv_size = btc_coin_export(val, coin);

    rc = mdb_put(txn, db->db_coin, &mkey, &mval, 0);
  }

  if (rc != 0 && rc != MDB_NOTFOUND) {
    fprintf(stderr, "mdb_put: %s\n", mdb_strerror(rc));
    return 0;
  }

  return 1;
}

static int
btc_chaindb_save_view(struct btc_chaindb_s *db,
                      MDB_txn *txn,
                      btc_view_t *view) {
  return btc_view_iterate(view, iterate_view, db, txn);
}

static btc_block_t *
btc_chaindb_read_block(struct btc_chaindb_s *db, btc_entry_t *entry) {
  (void)db;
  (void)entry;
  return NULL;
}

static btc_undo_t *
btc_chaindb_read_undo(struct btc_chaindb_s *db, btc_entry_t *entry) {
  (void)db;
  (void)entry;
  return NULL;
}

static int
btc_chaindb_write_block(struct btc_chaindb_s *db,
                        btc_entry_t *entry,
                        const btc_block_t *block) {
  (void)db;
  (void)entry;
  (void)block;
  return 1;
}

static int
btc_chaindb_write_undo(struct btc_chaindb_s *db,
                       btc_entry_t *entry,
                       btc_undo_t *undo) {
  (void)db;
  (void)entry;
  return 1;
}

static int
btc_chaindb_prune_block(struct btc_chaindb_s *db, btc_entry_t *entry) {
  (void)db;
  (void)entry;
  return 1;
}

static int
btc_chaindb_connect_block(struct btc_chaindb_s *db,
                          MDB_txn *txn,
                          btc_entry_t *entry,
                          const btc_block_t *block,
                          btc_view_t *view) {
  btc_undo_t *undo;

  (void)block;

  /* Genesis block's coinbase is unspendable. */
  if (entry->height == 0)
    return 1;

  /* Commit new coin state. */
  if (!btc_chaindb_save_view(db, txn, view))
    return 0;

  /* Write undo coins (if there are any). */
  undo = btc_view_undo(view);

  if (undo->length != 0) {
    if (entry->undo_pos == -1) {
      if (!btc_chaindb_write_undo(db, entry, undo))
        return 0;
    }

    btc_undo_reset(undo);
  }

  /* Prune height-288 if pruning is enabled. */
  return btc_chaindb_prune_block(db, entry);
}

static btc_view_t *
btc_chaindb_disconnect_block(struct btc_chaindb_s *db,
                             MDB_txn *txn,
                             btc_entry_t *entry,
                             const btc_block_t *block) {
  btc_view_t *view = btc_view_create();
  btc_undo_t *undo = btc_chaindb_read_undo(db, entry);
  const btc_input_t *input;
  const btc_tx_t *tx;
  btc_coin_t *coin;
  size_t i, j;

  /* Disconnect all transactions. */
  for (i = block->txs.length - 1; i != (size_t)-1; i--) {
    tx = block->txs.items[i];

    for (j = tx->inputs.length - 1; j != (size_t)-1; j--) {
      input = tx->inputs.items[i];
      coin = btc_undo_pop(undo);

      btc_view_put(view, &input->prevout, coin);
    }

    /* Remove any created coins. */
    btc_view_add(view, tx, entry->height, 1);
  }

  /* Undo coins should be empty. */
  CHECK(undo->length == 0);

  /* Commit new coin state. */
  if (!btc_chaindb_save_view(db, txn, view)) {
    btc_view_destroy(view);
    return NULL;
  }

  return view;
}

static int
btc_chaindb_save_block(struct btc_chaindb_s *db,
                       MDB_txn *txn,
                       btc_entry_t *entry,
                       const btc_block_t *block,
                       btc_view_t *view) {
  /* Write actual block data to flat file. */
  if (entry->block_pos == -1) {
    if (!btc_chaindb_write_block(db, entry, block))
      return 0;
  }

  if (view == NULL)
    return 1;

  return btc_chaindb_connect_block(db, txn, entry, block, view);
}

int
btc_chaindb_save(struct btc_chaindb_s *db,
                 btc_entry_t *entry,
                 const btc_block_t *block,
                 btc_view_t *view) {
  static const uint8_t tip_key[1] = {'R'};
  uint8_t raw[BTC_ENTRY_SIZE];
  MDB_val mkey, mval;
  MDB_txn *txn;
  khiter_t it;
  int rc = -1;

  /* Begin transaction. */
  if (mdb_txn_begin(db->env, NULL, 0, &txn) != 0)
    return 0;

  /* Connect block and save data. */
  if (!btc_chaindb_save_block(db, txn, entry, block, view))
    goto fail;

  /* Write entry data. */
  mkey.mv_data = entry->hash;
  mkey.mv_size = 32;
  mval.mv_data = raw;
  mval.mv_size = btc_entry_export(raw, entry);

  if (mdb_put(txn, db->db_index, &mkey, &mval, 0) != 0)
    goto fail;

  /* Clear old tip. */
  if (entry->height != 0) {
    mkey.mv_data = entry->header.prev_block;
    mkey.mv_size = 32;

    if (mdb_del(txn, db->db_tip, &mkey, NULL) != 0)
      goto fail;
  }

  /* Write new tip. */
  mkey.mv_data = entry->hash;
  mkey.mv_size = 32;
  mval.mv_data = raw;
  mval.mv_size = 1;

  if (mdb_put(txn, db->db_tip, &mkey, &mval, 0) != 0)
    goto fail;

  /* Write state (main chain only). */
  if (view != NULL) {
    mkey.mv_data = (uint8_t *)tip_key;
    mkey.mv_size = 1;
    mval.mv_data = entry->hash;
    mval.mv_size = 32;

    /* Commit new chain state. */
    if (mdb_put(txn, db->db_meta, &mkey, &mval, 0) != 0)
      goto fail;
  }

  /* Commit transaction. */
  if (mdb_txn_commit(txn) != 0)
    return 0;

  /* Update hashes. */
  it = kh_put(hashes, db->hashes, entry->hash, &rc);

  CHECK(rc > 0);

  kh_value(db->hashes, it) = entry;

  /* Main-chain-only stuff. */
  if (view != NULL) {
    /* Set next pointer. */
    if (entry->prev != NULL)
      entry->prev->next = entry;

    /* Update heights. */
    CHECK(db->heights.length == entry->height);
    btc_vector_push(&db->heights, entry);

    /* Update tip. */
    if (entry->height == 0)
      db->head = entry;

    db->tail = entry;
  }

  return 1;
fail:
  mdb_txn_abort(txn);
  return 0;
}

int
btc_chaindb_reconnect(struct btc_chaindb_s *db,
                      btc_entry_t *entry,
                      const btc_block_t *block,
                      btc_view_t *view) {
  static const uint8_t tip_key[1] = {'R'};
  MDB_val mkey, mval;
  MDB_txn *txn;

  /* Begin transaction. */
  if (mdb_txn_begin(db->env, NULL, 0, &txn) != 0)
    return 0;

  /* Connect inputs. */
  if (!btc_chaindb_connect_block(db, txn, entry, block, view))
    goto fail;

  /* Write state. */
  mkey.mv_data = (uint8_t *)tip_key;
  mkey.mv_size = 1;
  mval.mv_data = entry->hash;
  mval.mv_size = 32;

  /* Commit new chain state. */
  if (mdb_put(txn, db->db_meta, &mkey, &mval, 0) != 0)
    goto fail;

  /* Commit transaction. */
  if (mdb_txn_commit(txn) != 0)
    return 0;

  /* Set next pointer. */
  CHECK(entry->prev != NULL);
  entry->prev->next = entry;

  /* Update heights. */
  CHECK(db->heights.length == entry->height);
  btc_vector_push(&db->heights, entry);

  /* Update tip. */
  db->tail = entry;

  return 1;
fail:
  mdb_txn_abort(txn);
  return 0;
}

btc_view_t *
btc_chaindb_disconnect(struct btc_chaindb_s *db,
                       btc_entry_t *entry,
                       const btc_block_t *block) {
  static const uint8_t tip_key[1] = {'R'};
  MDB_val mkey, mval;
  btc_view_t *view;
  MDB_txn *txn;

  /* Begin transaction. */
  if (mdb_txn_begin(db->env, NULL, 0, &txn) != 0)
    return NULL;

  /* Disconnect inputs. */
  view = btc_chaindb_disconnect_block(db, txn, entry, block);

  if (view == NULL)
    goto fail;

  /* Revert chain state to previous tip. */
  mkey.mv_data = (uint8_t *)tip_key;
  mkey.mv_size = 1;
  mval.mv_data = entry->header.prev_block;
  mval.mv_size = 32;

  /* Commit new chain state. */
  if (mdb_put(txn, db->db_meta, &mkey, &mval, 0) != 0)
    goto fail;

  /* Commit transaction. */
  if (mdb_txn_commit(txn) != 0) {
    tx = NULL;
    goto fail;
  }

  /* Set next pointer. */
  CHECK(entry->prev != NULL);
  entry->prev->next = NULL;

  /* Update heights. */
  CHECK((btc_entry_t *)btc_vector_pop(&db->heights) == entry);

  /* Revert tip. */
  db->tail = entry->prev;

  return view;
fail:
  if (view != NULL)
    btc_view_destroy(view);

  mdb_txn_abort(txn);

  return NULL;
}
