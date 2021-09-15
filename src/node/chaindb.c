#include <lmdb.h>

struct btc_chaindb_s {
  MDB_env *env;
  MDB_txn *txn;
  MDB_dbi db_meta;
  MDB_dbi db_coin;
  MDB_dbi db_entry;
  MDB_dbi db_tip;
};

int
btc_chaindb_open(struct btc_chaindb_s *db, const char *path, size_t map_size) {
  int flags = 0;
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

  rc = mdb_dbi_open(txn, "coins", MDB_CREATE, &db->db_coin);

  if (rc != 0) {
    fprintf(stderr, "mdb_dbi_open: %s\n", mdb_strerror(rc));
    mdb_txn_abort(txn);
    mdb_env_close(db->env);
    return 0;
  }

  rc = mdb_dbi_open(txn, "entries", MDB_CREATE, &db->db_entry);

  if (rc != 0) {
    fprintf(stderr, "mdb_dbi_open: %s\n", mdb_strerror(rc));
    mdb_txn_abort(txn);
    mdb_env_close(db->env);
    return 0;
  }

  rc = mdb_dbi_open(txn, "tips", MDB_CREATE, &db->db_tip);

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

  db->txn = NULL;

  return 1;
}

void
btc_chaindb_close(struct btc_chaindb_s *db) {
  mdb_dbi_close(db->env, db->db_meta);
  mdb_dbi_close(db->env, db->db_coin);
  mdb_dbi_close(db->env, db->db_entry);
  mdb_env_close(db->env);
}

static btc_coin_t *
read_coin(void *ctx, void *arg, const btc_outpoint_t *prevout) {
  struct btc_chaindb_s *db = (struct btc_chaindb_s *)ctx;
  MDB_txn *txn = (MDB_txn *)arg;
  uint8_t key[36];
  MDB_val mkey, mval;
  btc_coin_t *coin;

  btc_outpoint_write(key, prevout);

  mkey.mv_data = (uint8_t *)key;
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
  MDB_val mkey, mval;
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
  uint8_t key[36];

  btc_raw_write(key, hash, 32);
  btc_uint32_write(key + 32, index);

  mkey.mv_data = (uint8_t *)key;
  mkey.mv_size = klen;

  if (coin->spent) {
    rc = mdb_del(db->txn, db->db_coin, &mkey, NULL);
  } else {
    mval.mv_data = (uint8_t *)val;
    mval.mv_size = btc_coin_export(val, coin);

    rc = mdb_put(db->txn, db->db_coin, &mkey, &mval, 0);
  }

  if (rc != 0 && rc != MDB_NOTFOUND) {
    fprintf(stderr, "mdb_put: %s\n", mdb_strerror(rc));
    return 0;
  }

  return 1;
}

void
btc_chaindb_save_view(struct btc_chaindb_s *db,
                      MDB_txn *txn,
                      btc_view_t *view) {
  return btc_view_iterate(view, iterate_view, db, txn);
}
