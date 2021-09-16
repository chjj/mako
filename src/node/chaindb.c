#include <lmdb.h>
#include "../map.h"
#include "../impl.h"
#include "../internal.h"

/*
 * Constants
 */

static const uint8_t tip_key[1] = {'R'};
static const uint8_t blockfile_key[1] = {'B'};
static const uint8_t undofile_key[1] = {'U'};

/*
 * Chain File
 */

struct btc_chainfile_s {
  int fd;
  int file;
  int pos;
  int min_height;
  int max_height;
} btc_chainfile_t;

DEFINE_SERIALIZABLE_OBJECT(btc_chainfile, SCOPE_EXTERN)

void
btc_chainfile_init(btc_chainfile_t *z) {
  z->fd = -1;
  z->file = 0;
  z->pos = 0;
  z->min_height = -1;
  z->max_height = -1;
}

void
btc_chainfile_clear(btc_chainfile_t *z) {
  btc_chainfile_init(z);
}

void
btc_chainfile_copy(btc_chainfile_t *z, const btc_chainfile_t *x) {
  z->fd = -1;
  z->file = x->file;
  z->pos = x->pos;
  z->min_height = x->min_height;
  z->max_height = x->max_height;
}

size_t
btc_chainfile_size(const btc_chainfile_t *x) {
  return 16;
}

uint8_t *
btc_chainfile_write(uint8_t *zp, const btc_chainfile_t *x) {
  zp = btc_int32_write(zp, x->file);
  zp = btc_int32_write(zp, x->pos);
  zp = btc_int32_write(zp, x->min_height);
  zp = btc_int32_write(zp, x->max_height);
  return zp;
}

int
btc_chainfile_read(btc_chainfile_t *z, const uint8_t **xp, size_t *xn) {
  if (!btc_int32_read(&z->file, xp, xn))
    return 0;

  if (!btc_int32_read(&z->pos, xp, xn))
    return 0;

  if (!btc_int32_read(&z->min_height, xp, xn))
    return 0;

  if (!btc_int32_read(&z->max_height, xp, xn))
    return 0;

  return 1;
}

/*
 * Chain Database
 */

KHASH_MAP_INIT_CONST_HASH(hashes, btc_entry_t *)

struct btc_chaindb_s {
  char prefix[1024];
  const btc_network_t *network;
  MDB_env *env;
  MDB_dbi db_meta;
  MDB_dbi db_coin;
  MDB_dbi db_index;
  MDB_dbi db_tip;
  MDB_dbi db_blockfile;
  MDB_dbi db_undofile;
  khash_t(hashes) *hashes;
  btc_vector_t heights;
  btc_entry_t *head;
  btc_entry_t *tail;
  btc_vector_t blockfiles;
  btc_vector_t undofiles;
  btc_chainfile_t block;
  btc_chainfile_t undo;
  uint8_t *slab;
};

static void
btc_chaindb_init(struct btc_chaindb_s *db, const btc_network_t *network) {
  memset(db, 0, sizeof(*db));

  db->network = network;
  db->hashes = kh_init(hashes);

  btc_vector_init(&db->heights);
  btc_vector_init(&db->blockfiles);
  btc_vector_init(&db->undofiles);

  CHECK(db->hash != NULL);

  db->slab = (uint8_t *)malloc(4 + BTC_MAX_RAW_BLOCK_SIZE);

  CHECK(db->slab != NULL);
}

static void
btc_chaindb_clear(struct btc_chaindb_s *db) {
  kh_destroy(hashes, db->hashes);
  btc_vector_clear(&db->heights);
  btc_vector_clear(&db->blockfiles);
  btc_vector_clear(&db->undofiles);
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
btc_chaindb_open(struct btc_chaindb_s *db, const char *prefix, size_t map_size) {
  int flags = MDB_NOTLS;
  char path[1024];
  MDB_txn *txn;
  int rc;

  {
    CHECK(strlen(prefix) <= 1000);

    strcpy(db->prefix, prefix);

    if (!btc_fs_exists(prefix) && !btc_fs_mkdir(prefix))
      return 0;

    sprintf(path, "%s/blocks", prefix);

    if (!btc_fs_exists(path) && !btc_fs_mkdir(path))
      return 0;

    sprintf(path, "%s/chain", prefix);
  }

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

  rc = mdb_dbi_open(txn, "blockfile", MDB_CREATE, &db->db_blockfile);

  if (rc != 0) {
    fprintf(stderr, "mdb_dbi_open: %s\n", mdb_strerror(rc));
    mdb_txn_abort(txn);
    mdb_env_close(db->env);
    return 0;
  }

  rc = mdb_dbi_open(txn, "undofile", MDB_CREATE, &db->db_undofile);

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

  /* Read file info. */
  {
    int block_found = 0;
    int undo_found = 0;
    btc_chainfile_t *file;
    MDB_val mkey, mval;

    CHECK(mdb_txn_begin(db->env, NULL, MDB_RDONLY, &txn) == 0);

    /* Read best block file. */
    mkey.mv_data = (uint8_t *)blockfile_key;
    mkey.mv_size = 1;

    rc = mdb_get(txn, db->db_meta, &mkey, &mval);

    if (rc != MDB_NOTFOUND) {
      CHECK(rc == 0);
      CHECK(btc_chainfile_import(&db->block, mval.mv_data, mval.mv_size));
      block_found = 1;
    }

    /* Read best undo file. */
    mkey.mv_data = (uint8_t *)undofile_key;
    mkey.mv_size = 1;

    rc = mdb_get(txn, db->db_meta, &mkey, &mval);

    if (rc != MDB_NOTFOUND) {
      CHECK(rc == 0);
      CHECK(btc_chainfile_import(&db->undo, mval.mv_data, mval.mv_size));
      undo_found = 1;
    }

    CHECK(block_found == undo_found);

    /* Read block file index. */
    btc_chainfile_init(&db->block);

    CHECK(mdb_cursor_open(txn, db->db_blockfile, &cur) == 0);

    rc = mdb_cursor_get(cur, &mkey, &mval, MDB_FIRST);

    while (rc == 0) {
      file = btc_chainfile_create();

      CHECK(btc_chainfile_import(file, mval.mv_data, mval.mv_size));

      btc_vector_push(&db->blockfiles, file);

      rc = mdb_cursor_get(cur, &mkey, &mval, MDB_NEXT);
    }

    CHECK(rc == MDB_NOTFOUND);

    mdb_cursor_close(cur);

    /* Read undo file index. */
    btc_chainfile_init(&db->undo);

    CHECK(mdb_cursor_open(txn, db->db_undofile, &cur) == 0);

    rc = mdb_cursor_get(cur, &mkey, &mval, MDB_FIRST);

    while (rc == 0) {
      file = btc_chainfile_create();

      CHECK(btc_chainfile_import(file, mval.mv_data, mval.mv_size));

      btc_vector_push(&db->undofiles, file);

      rc = mdb_cursor_get(cur, &mkey, &mval, MDB_NEXT);
    }

    CHECK(rc == MDB_NOTFOUND);

    mdb_cursor_close(cur);

    mdb_txn_abort(txn);

    /* Open block file for writing. */
    sprintf(path, "%s/blocks/blk%09d.dat", prefix, db->block.file);

    if (block_found) {
      db->block.fd = btc_fs_open(path, BTC_O_RDWR, 0664);

      CHECK(db->block.fd != -1);
    } else {
      db->block.fd = btc_fs_open(path, BTC_O_RDWR | BTC_O_CREAT, 0664);

      CHECK(db->block.fd != -1);
      CHECK(btc_fs_ftruncate(db->block.fd, 128 << 20));
    }

    /* Open undo file for writing. */
    sprintf(path, "%s/blocks/rev%09d.dat", prefix, db->undo.file);

    if (undo_found) {
      db->undo.fd = btc_fs_open(path, BTC_O_RDWR, 0664);

      CHECK(db->undo.fd != -1);
    } else {
      db->undo.fd = btc_fs_open(path, BTC_O_RDWR | BTC_O_CREAT, 0664);

      CHECK(db->undo.fd != -1);
      CHECK(btc_fs_ftruncate(db->undo.fd, 128 << 20));
    }
  }

  btc_chaindb_load(db);

  return 1;
}

void
btc_chaindb_close(struct btc_chaindb_s *db) {
  btc_chainfile_t *file;

  btc_chaindb_unload(db);

  btc_fs_close(db->block.fd);
  btc_fs_close(db->undo.fd);

  while (db->blockfiles.length > 0) {
    file = (btc_chainfile_t *)btc_vector_pop(&btc->blockfiles);
    btc_chainfile_destroy(file);
  }

  while (db->undofiles.length > 0) {
    file = (btc_chainfile_t *)btc_vector_pop(&btc->undofiles);
    btc_chainfile_destroy(file);
  }

  mdb_dbi_close(db->env, db->db_meta);
  mdb_dbi_close(db->env, db->db_coin);
  mdb_dbi_close(db->env, db->db_index);
  mdb_dbi_close(db->env, db->db_tip);
  mdb_dbi_close(db->env, db->db_blockfile);
  mdb_dbi_close(db->env, db->db_undofile);
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
  btc_entry_t *entry, *tip;
  btc_entry_t *gen = NULL;
  uint8_t tip_hash[32];
  MDB_val mkey, mval;
  khiter_t it, iter;
  MDB_cursor *cur;
  MDB_txn *txn;
  int rc;

  CHECK(mdb_txn_begin(db->env, NULL, MDB_RDONLY, &txn) == 0);

  /* Read tip. */
  {
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
  }

  /* Read block index. */
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

  /* Create hash table. */
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

static int
btc_chaindb_read(struct btc_chaindb_s *db,
                 uint8_t **raw,
                 size_t *len,
                 const char *type,
                 int file,
                 int pos) {
  uint8_t *buf = NULL;
  char path[1024];
  uint8_t tmp[4];
  size_t size;
  int ret = 0;
  int fd;

  sprintf(path, "%s/blocks/%s%09d.dat", db->prefix, type, file);

  fd = btc_fs_open(path, O_RDONLY, 0);

  if (fd == -1)
    return 0;

  if (!btc_fs_pread(fd, tmp, 4, pos))
    goto fail;

  size = read32le(tmp);
  buf = (uint8_t *)malloc(size);

  if (buf == NULL)
    goto fail;

  if (!btc_fs_pread(fd, buf, size, pos + 4))
    goto fail;

  *raw = buf;
  *len = size;

  buf = NULL;
  ret = 1;
fail:
  if (buf != NULL)
    free(buf);

  btc_fs_close(fd);

  return ret;
}

static btc_block_t *
btc_chaindb_read_block(struct btc_chaindb_s *db, btc_entry_t *entry) {
  btc_block_t *ret = NULL;
  btc_block_t *block;
  uint8_t *buf;
  size_t len;

  if (entry->block_pos == -1)
    return NULL;

  if (!btc_chaindb_read(db, &buf, &len, "blk", entry->block_file,
                                               entry->block_pos)) {
    return NULL;
  }

  block = btc_block_create();

  if (!btc_block_import(block, buf, len)) {
    btc_block_destroy(block);
    goto fail;
  }

  ret = block;
fail:
  free(buf);
  return ret;
}

static btc_undo_t *
btc_chaindb_read_undo(struct btc_chaindb_s *db, btc_entry_t *entry) {
  btc_undo_t *ret = NULL;
  btc_undo_t *undo;
  uint8_t *buf;
  size_t len;

  if (entry->undo_pos == -1)
    return btc_undo_create();

  if (!btc_chaindb_read(db, &buf, &len, "rev", entry->undo_file,
                                               entry->undo_pos)) {
    return NULL;
  }

  undo = btc_undo_create();

  if (!btc_undo_import(undo, buf, len)) {
    btc_undo_destroy(undo);
    goto fail;
  }

  ret = undo;
fail:
  free(buf);
  return ret;
}

static int
btc_chaindb_should_sync(struct btc_chaindb_s *db, btc_entry_t *entry) {
  time_t now = time(NULL):

  if (now == (time_t)-1)
    return 1;

  if ((uint32_t)now < entry->time)
    return 1;

  if ((uint32_t)now - entry->time <= 24 * 60 * 60)
    return 1;

  if ((entry->height % 1000) == 0)
    return 1;

  return 0;
}

static int
btc_chaindb_blockfile_alloc(struct btc_chaindb_s *db, MDB_txn *txn, size_t len) {
  if (db->block.pos + len > (128 << 20)) {
    MDB_val mkey, mval;
    char path[1024];
    uint8_t raw[16];
    uint8_t key[4];
    int fd;

    write32be(key, db->block.file);

    mkey.mv_data = key;
    mkey.mv_size = 4;
    mval.mv_data = raw;
    mval.mv_size = btc_chainfile_export(raw, &db->block);

    if (mdb_put(txn, db->db_blockfile, &mkey, &mval, 0) != 0)
      return 0;

    sprintf(path, "%s/blocks/blk%09d.dat", db->prefix, db->block.file + 1);

    fd = btc_fs_open(path, BTC_O_RDWR | BTC_O_CREAT, 0664);

    if (fd == -1)
      return 0;

    if (!btc_fs_ftruncate(fd, 128 << 20)) {
      btc_fs_close(fd);
      return 0;
    }

    btc_fs_fsync(db->block.fd);
    btc_fs_close(db->block.fd);

    btc_vector_push(&db->blockfiles, btc_chainfile_clone(&db->block));

    db->block.fd = fd;
    db->block.file++;
    db->block.pos = 0;
    db->block.min_height = -1;
    db->block.max_height = -1;
  }

  return 1;
}

static int
btc_chaindb_undofile_alloc(struct btc_chaindb_s *db, MDB_txn *txn, size_t len) {
  if (db->undo.pos + len > (128 << 20)) {
    MDB_val mkey, mval;
    char path[1024];
    uint8_t raw[16];
    uint8_t key[4];
    int fd;

    write32be(key, db->undo.file);

    mkey.mv_data = key;
    mkey.mv_size = 4;
    mval.mv_data = raw;
    mval.mv_size = btc_chainfile_export(raw, &db->undo);

    if (mdb_put(txn, db->db_undofile, &mkey, &mval, 0) != 0)
      return 0;

    sprintf(path, "%s/blocks/rev%09d.dat", db->prefix, db->undo.file + 1);

    fd = btc_fs_open(path, BTC_O_RDWR | BTC_O_CREAT, 0664);

    if (fd == -1)
      return 0;

    if (!btc_fs_ftruncate(fd, 128 << 20)) {
      btc_fs_close(fd);
      return 0;
    }

    btc_fs_fsync(db->undo.fd);
    btc_fs_close(db->undo.fd);

    btc_vector_push(&db->undofiles, btc_chainfile_clone(&db->undo));

    db->undo.fd = fd;
    db->undo.file++;
    db->undo.pos = 0;
    db->undo.min_height = -1;
    db->undo.max_height = -1;
  }

  return 1;
}

static int
btc_chaindb_write_block(struct btc_chaindb_s *db,
                        MDB_txn *txn,
                        btc_entry_t *entry,
                        const btc_block_t *block) {
  size_t len = btc_block_export(db->slab + 4, block);

  btc_uint32_write(db->slab, len);

  len += 4;

  if (!btc_chaindb_blockfile_alloc(db, txn, len))
    return 0;

  if (!btc_fs_pwrite(db->block.fd, db->slab, len, db->block.pos))
    return 0;

  if (btc_chaindb_should_sync(db, entry))
    btc_fs_fsync(db->block.fd);

  entry->block_file = db->block.file;
  entry->block_pos = db->block.pos;

  db->block.pos += len;

  if (db->block.min_height == -1 || entry.height < db->block.min_height)
    db->block.min_height = entry.height;

  if (db->block.max_height == -1 || entry.height > db->block.max_height)
    db->block.max_height = entry.height;

  {
    MDB_val mkey, mval;
    uint8_t raw[16];

    mkey.mv_data = (uint8_t *)blockfile_key;
    mkey.mv_size = 1;
    mval.mv_data = raw;
    mval.mv_size = btc_chainfile_export(raw, &db->block);

    if (mdb_put(txn, db->db_blockfile, &mkey, &mval, 0) != 0)
      return 0;
  }

  return 1;
}

static int
btc_chaindb_write_undo(struct btc_chaindb_s *db,
                       MDB_txn *txn,
                       btc_entry_t *entry,
                       btc_undo_t *undo) {
  size_t len = btc_undo_size(undo);
  uint8_t *buf = db->slab;
  int ret = 0;

  if (len > BTC_MAX_RAW_BLOCK_SIZE) {
    buf = (uint8_t *)malloc(4 + len);

    CHECK(buf != NULL);
  }

  btc_uint32_write(buf, len);
  btc_undo_export(buf + 4, block);

  len += 4;

  if (!btc_chaindb_undofile_alloc(db, txn, len))
    goto fail;

  if (!btc_fs_pwrite(db->undo.fd, buf, len, db->undo.pos))
    goto fail;

  if (btc_chaindb_should_sync(db, entry))
    btc_fs_fsync(db->undo.fd);

  entry->undo_file = db->undo.file;
  entry->undo_pos = db->undo.pos;

  db->undo.pos += len;

  if (db->undo.min_height == -1 || entry.height < db->undo.min_height)
    db->undo.min_height = entry.height;

  if (db->undo.max_height == -1 || entry.height > db->undo.max_height)
    db->undo.max_height = entry.height;

  {
    MDB_val mkey, mval;
    uint8_t raw[16];

    mkey.mv_data = (uint8_t *)undofile_key;
    mkey.mv_size = 1;
    mval.mv_data = raw;
    mval.mv_size = btc_chainfile_export(raw, &db->undo);

    if (mdb_put(txn, db->db_undofile, &mkey, &mval, 0) != 0)
      goto fail;
  }

  ret = 1;
fail:
  if (buf != db->slab)
    free(buf);

  return ret;
}

static int
btc_chaindb_prune_files(struct btc_chaindb_s *db, btc_entry_t *entry) {
  int keep = db->network->block.keep_blocks;
  btc_chainfile_t *file;
  MDB_val mkey, mval;
  char path[1024];
  uint8_t key[4];
  int target;
  size_t i;

  if (entry->height < db->network->block.keep_blocks)
    return 1;

  target = entry->height - keep;

  if (target <= (int)db->network->block.prune_after_height)
    return 1;

  for (i = 0; i < db->blockfiles.length; i++) {
    file = (btc_chainfile_t *)db->blockfiles.items[i];

    if (file->max_height >= target)
      continue;

    sprintf(path, "%s/blocks/blk%09d.dat", db->prefix, file->file);

    btc_fs_unlink(path);

    write32be(key, file->file);

    mkey.mv_data = key;
    mkey.mv_size = 4;

    if (mdb_del(txn, db->db_blockfile, &mkey, NULL) != 0)
      return 0;

    if (i != db->blockfiles.length - 1)
      db->blockfiles.items[i--] = db->blockfiles.items[db->blockfiles.length - 1];

    db->blockfiles.length--;

    btc_chainfile_destroy(file);
  }

  for (i = 0; i < db->undofiles.length; i++) {
    file = (btc_chainfile_t *)db->undofiles.items[i];

    if (file->max_height >= target)
      continue;

    sprintf(path, "%s/blocks/rev%09d.dat", db->prefix, file->file);

    btc_fs_unlink(path);

    write32be(key, file->file);

    mkey.mv_data = key;
    mkey.mv_size = 4;

    if (mdb_del(txn, db->db_undofile, &mkey, NULL) != 0)
      return 0;

    if (i != db->undofiles.length - 1)
      db->undofiles.items[i--] = db->undofiles.items[db->undofiles.length - 1];

    db->undofiles.length--;

    btc_chainfile_destroy(file);
  }

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
      if (!btc_chaindb_write_undo(db, txn, entry, undo))
        return 0;
    }

    btc_undo_reset(undo);
  }

  /* Prune height-288 if pruning is enabled. */
  return btc_chaindb_prune_files(db, entry);
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

  if (undo == NULL)
    return NULL;

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
  /* Write actual block data. */
  if (entry->block_pos == -1) {
    if (!btc_chaindb_write_block(db, txn, entry, block))
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
  uint8_t *raw = db->slab;
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
