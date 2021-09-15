/*!
 * db.c - lmdb wrapper for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <lmdb.h>
#include <node/db.h>
#include "../internal.h"

/*
 * Types
 */

struct btc_db_s {
  MDB_dbi dbi;
  MDB_env *env;
};

struct btc_batch_s {
  MDB_dbi dbi;
  MDB_txn *txn;
};

struct btc_iter_s {
  MDB_txn *txn;
  MDB_cursor *cur;
  MDB_val mkey;
  MDB_val mval;
  int rc;
};

/*
 * Database
 */

struct btc_db_s *
btc_db_create(void) {
  struct btc_db_s *db = (struct btc_db_s *)malloc(sizeof(struct btc_db_s *));

  CHECK(db != NULL);

  db->env = NULL;

  return db;
}

int
btc_db_open(struct btc_db_s *db, const char *path, size_t map_size) {
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

  rc = mdb_dbi_open(txn, NULL, 0, &db->dbi);

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

  return 1;
}

void
btc_db_close(struct btc_db_s *db) {
  mdb_dbi_close(db->env, db->dbi);
  mdb_env_close(db->env);
  db->env = NULL;
}

void
btc_db_destroy(struct btc_db_s *db) {
  if (db->env != NULL)
    btc_db_close(db);

  free(db);
}

int
btc_db_get(struct btc_db_s *db, unsigned char **val, size_t *vlen,
                                const unsigned char *key, size_t klen) {
  MDB_val mkey, mval;
  MDB_txn *txn;
  int rc;

  rc = mdb_txn_begin(db->env, NULL, MDB_RDONLY, &txn);

  if (rc != 0) {
    fprintf(stderr, "mdb_txn_begin: %s\n", mdb_strerror(rc));
    return 0;
  }

  mkey.mv_data = (unsigned char *)key;
  mkey.mv_size = klen;

  rc = mdb_get(txn, db->dbi, &mkey, &mval);

  if (rc != 0) {
    fprintf(stderr, "mdb_get: %s\n", mdb_strerror(rc));
    mdb_txn_abort(txn);
    return 0;
  }

  if (mval.mv_size > 0) {
    *val = (unsigned char *)malloc(mval.mv_size);
    *vlen = mval.mv_size;

    CHECK(*val != NULL);

    memcpy(*val, mval.mv_data, mval.mv_size);
  } else {
    *val = NULL;
    *vlen = 0;
  }

  rc = mdb_txn_commit(txn);

  if (rc != 0) {
    fprintf(stderr, "mdb_txn_commit: %s\n", mdb_strerror(rc));
    return 0;
  }

  return 1;
}

int
btc_db_put(struct btc_db_s *db, const unsigned char *key, size_t klen,
                                const unsigned char *val, size_t vlen) {
  MDB_val mkey, mval;
  MDB_txn *txn;
  int rc;

  rc = mdb_txn_begin(db->env, NULL, 0, &txn);

  if (rc != 0) {
    fprintf(stderr, "mdb_txn_begin: %s\n", mdb_strerror(rc));
    return 0;
  }

  mkey.mv_data = (unsigned char *)key;
  mkey.mv_size = klen;

  mval.mv_data = (unsigned char *)val;
  mval.mv_size = vlen;

  rc = mdb_put(txn, db->dbi, &mkey, &mval, 0);

  if (rc != 0) {
    fprintf(stderr, "mdb_put: %s\n", mdb_strerror(rc));
    mdb_txn_abort(txn);
    return 0;
  }

  rc = mdb_txn_commit(txn);

  if (rc != 0) {
    fprintf(stderr, "mdb_txn_commit: %s\n", mdb_strerror(rc));
    return 0;
  }

  return 1;
}

int
btc_db_del(struct btc_db_s *db, const unsigned char *key, size_t klen) {
  MDB_val mkey;
  MDB_txn *txn;
  int rc;

  rc = mdb_txn_begin(db->env, NULL, 0, &txn);

  if (rc != 0) {
    fprintf(stderr, "mdb_txn_begin: %s\n", mdb_strerror(rc));
    return 0;
  }

  mkey.mv_data = (unsigned char *)key;
  mkey.mv_size = klen;

  rc = mdb_del(txn, db->dbi, &mkey, NULL);

  if (rc != 0 && rc != MDB_NOTFOUND) {
    fprintf(stderr, "mdb_del: %s\n", mdb_strerror(rc));
    mdb_txn_abort(txn);
    return 0;
  }

  rc = mdb_txn_commit(txn);

  if (rc != 0) {
    fprintf(stderr, "mdb_txn_commit: %s\n", mdb_strerror(rc));
    return 0;
  }

  return 1;
}

int
btc_db_write(struct btc_db_s *db, struct btc_batch_s *bat) {
  int rc = mdb_txn_commit(bat->txn);

  (void)db;

  bat->txn = NULL;

  if (rc != 0) {
    fprintf(stderr, "mdb_txn_commit: %s\n", mdb_strerror(rc));
    return 0;
  }

  return 1;
}

/*
 * Batch
 */

struct btc_batch_s *
btc_batch_create(struct btc_db_s *db) {
  struct btc_batch_s *bat =
    (struct btc_batch_s *)malloc(sizeof(struct btc_batch_s));
  int rc;

  CHECK(bat != NULL);

  rc = mdb_txn_begin(db->env, NULL, 0, &bat->txn);

  if (rc != 0) {
    fprintf(stderr, "mdb_txn_begin: %s\n", mdb_strerror(rc));
    goto fail;
  }

  bat->dbi = db->dbi;

  return bat;
fail:
  free(bat);
  return NULL;
}

void
btc_batch_destroy(struct btc_batch_s *bat) {
  if (bat->txn != NULL)
    mdb_txn_abort(bat->txn);

  free(bat);
}

void
btc_batch_put(struct btc_batch_s *bat, const unsigned char *key, size_t klen,
                                       const unsigned char *val, size_t vlen) {
  MDB_val mkey, mval;

  mkey.mv_data = (unsigned char *)key;
  mkey.mv_size = klen;

  mval.mv_data = (unsigned char *)val;
  mval.mv_size = vlen;

  CHECK(mdb_put(bat->txn, bat->dbi, &mkey, &mval, 0) == 0);
}

void
btc_batch_del(struct btc_batch_s *bat, const unsigned char *key, size_t klen) {
  MDB_val mkey;
  int rc;

  mkey.mv_data = (unsigned char *)key;
  mkey.mv_size = klen;

  rc = mdb_del(bat->txn, bat->dbi, &mkey, NULL);

  CHECK(rc == 0 || rc == MDB_NOTFOUND);
}

/*
 * Iterator
 */

struct btc_iter_s *
btc_iter_create(struct btc_db_s *db, int use_snapshot) {
  struct btc_iter_s *iter =
    (struct btc_iter_s *)malloc(sizeof(struct btc_iter_s));
  int rc;

  (void)use_snapshot;

  CHECK(iter != NULL);

  rc = mdb_txn_begin(db->env, NULL, MDB_RDONLY, &iter->txn);

  if (rc != 0) {
    fprintf(stderr, "mdb_txn_begin: %s\n", mdb_strerror(rc));
    goto fail;
  }

  rc = mdb_cursor_open(iter->txn, db->dbi, &iter->cur);

  if (rc != 0) {
    fprintf(stderr, "mdb_cursor_open: %s\n", mdb_strerror(rc));
    goto fail;
  }

  iter->mkey.mv_data = NULL;
  iter->mkey.mv_size = 0;
  iter->mval.mv_data = NULL;
  iter->mval.mv_data = 0;
  iter->rc = 0;

  return iter;
fail:
  free(iter);
  return NULL;
}

void
btc_iter_destroy(struct btc_iter_s *iter) {
  mdb_cursor_close(iter->cur);
  mdb_txn_abort(iter->txn);
  free(iter);
}

int
btc_iter_valid(const struct btc_iter_s *iter) {
  return iter->rc == 0;
}

void
btc_iter_seek_first(struct btc_iter_s *iter) {
  iter->rc = mdb_cursor_get(iter->cur, &iter->mkey, &iter->mval, MDB_FIRST);
}

void
btc_iter_seek_last(struct btc_iter_s *iter) {
  iter->rc = mdb_cursor_get(iter->cur, &iter->mkey, &iter->mval, MDB_LAST);
}

void
btc_iter_seek(struct btc_iter_s *iter, const unsigned char *key, size_t klen) {
  iter->mkey.mv_data = (unsigned char *)key;
  iter->mkey.mv_size = klen;
  iter->rc = mdb_cursor_get(iter->cur, &iter->mkey, &iter->mval, MDB_SET_RANGE);
}

void
btc_iter_next(struct btc_iter_s *iter) {
  iter->rc = mdb_cursor_get(iter->cur, &iter->mkey, &iter->mval, MDB_NEXT);
}

void
btc_iter_prev(struct btc_iter_s *iter) {
  iter->rc = mdb_cursor_get(iter->cur, &iter->mkey, &iter->mval, MDB_PREV);
}

const unsigned char *
btc_iter_key(const struct btc_iter_s *iter, size_t *klen) {
  *klen = iter->mkey.mv_size;
  return iter->mkey.mv_data;
}

const unsigned char *
btc_iter_val(const struct btc_iter_s *iter, size_t *vlen) {
  *vlen = iter->mval.mv_size;
  return iter->mval.mv_data;
}

int
btc_iter_check(const struct btc_iter_s *iter) {
  if (iter->rc != 0) {
    fprintf(stderr, "mdb_cursor: %s\n", mdb_strerror(iter->rc));
    return 0;
  }
  return 1;
}

/*
 * Util
 */

void
btc_db_free(void *ptr) {
  free(ptr);
}
