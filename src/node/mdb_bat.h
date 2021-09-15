/* Idea: implement write batches for lmdb.
   The buffering allows us to abort and retry a transaction on MDB_MAP_FULL.
   This allows us to create a transparently growing database. */

#include <stdlib.h>
#include <string.h>
#include <lmdb.h>
#include "../impl.h"

typedef struct MDB_bat_op_s {
  int type;
  MDB_dbi dbi;
  MDB_val key;
  MDB_val val;
  int has_val;
  unsigned int flags;
} MDB_bat_op;

typedef struct MDB_bat_s {
  MDB_env *env;
  MDB_txn *parent;
  unsigned int flags;
  MDB_bat_op **items;
  size_t alloc;
  size_t length;
} MDB_bat;

typedef MDB_bat MDB_bat_t;
typedef MDB_bat_op MDB_bat_op_t;

DEFINE_VECTOR(MDB_bat, MDB_bat_op, SCOPE_STATIC)

#define DEFAULT_MAPSIZE 1048576

static int
mdb_env_init_mapsize(MDB_env *env, mdb_size_t size) {
  /* Only call mdb_env_set_mapsize on initialization. */
  /* Must be called _after_ mdb_env_open. */
  MDB_envinfo info;
  int rc;

  if (size == DEFAULT_MAPSIZE)
    return 0;

  rc = mdb_env_info(env, &info);

  if (rc != 0)
    return rc;

  if (info.me_mapsize == DEFAULT_MAPSIZE)
    return mdb_env_set_mapsize(env, size);

  return 0;
}

static int
mdb_bat_begin(MDB_env *env, MDB_txn *parent, unsigned int flags, MDB_bat **bat) {
  *bat = mdb_bat_create();
  *bat->env = env;
  *bat->parent = parent;
  *bat->flags = flags;
  return 0;
}

static MDB_bat_op *
mdb_bat_op(MDB_bat *bat, MDB_dbi dbi, MDB_val *key, MDB_val *val, unsigned int flags) {
  MDB_bat_op *op = (MDB_bat_op *)malloc(sizeof(MDB_bat_op));

  CHECK(op != NULL);

  op->dbi = dbi;
  op->key.mv_data = NULL;
  op->key.mv_size = key->mv_size;
  op->val.mv_data = NULL;
  op->val.mv_size = val != NULL ? val->mv_size : 0;
  op->has_val = (val != NULL);

  if (key->mv_size > 0) {
    op->key.mv_data = (unsigned char *)malloc(key->mv_size);

    CHECK(op->key.mv_data != NULL);

    memcpy(op->key.mv_data, key->mv_data, key->mv_size);
  }

  if (val != NULL && val->mv_size > 0) {
    op->val.mv_data = (unsigned char *)malloc(val->mv_size);

    CHECK(op->val.mv_data != NULL);

    memcpy(op->val.mv_data, val->mv_data, val->mv_size);
  }

  return op;
}

static int
mdb_bat_put(MDB_bat *bat, MDB_dbi dbi, MDB_val *key, MDB_val *val, unsigned int flags) {
  MDB_bat_op *op = MDB_bat_op(bat, dbi, key, val, flags);

  op->type = 0;

  mdb_bat_push(bat, op);

  return 0;
}

static int
mdb_bat_del(MDB_bat *bat, MDB_dbi dbi, MDB_val *key, MDB_val *val) {
  MDB_bat_op *op = MDB_bat_op(bat, dbi, key, val, 0);

  op->type = 1;

  mdb_bat_push(bat, op);

  return 0;
}

static int
mdb_bat_commit(MDB_bat *bat) {
  MDB_txn *txn;
  MDB_bat_op *op;
  size_t i;
  int rc;

retry:
  rc = mdb_txn_begin(bat->env, bat->parent, bat->flags, &txn);

  if (rc != 0) {
    mdb_bat_destroy(bat);
    return rc;
  }

  for (i = 0; i < bat->length; i++) {
    op = bat->items[i];

    if (op->type == 0)
      rc = mdb_put(txn, op->dbi, &op->key, &op->val, op->flags);
    else if (op->has_val)
      rc = mdb_del(txn, op->dbi, &op->key, &op->val);
    else
      rc = mdb_del(txn, op->dbi, &op->key, NULL);

    if (op->type == 1 && rc == MDB_NOTFOUND)
      continue;

    if (op->type == 0 && rc == MDB_MAP_FULL) {
      MDB_envinfo info;
      size_t size;

      mdb_txn_abort(txn);

      rc = mdb_env_info(bat->env, &info);

      if (rc != 0) {
        mdb_bat_destroy(bat);
        return rc;
      }

      size = info.me_mapsize;

      if (size > (1 << 30))
        size += (1 << 30);
      else
        size *= 2;

      rc = mdb_env_set_mapsize(bat->env, size);

      if (rc != 0) {
        mdb_bat_destroy(bat);
        return rc;
      }

      goto retry;
    }

    if (rc != 0) {
      mdb_txn_abort(txn);
      mdb_bat_destroy(bat);
      return rc;
    }
  }

  rc = mdb_txn_commit(txn);

  mdb_bat_destroy(bat);

  return rc;
}

static void
mdb_bat_abort(MDB_bat *bat) {
  mdb_bat_destroy(bat);
}
