/*!
 * chaindb.c - chaindb for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <lsm.h>

#include <io/core.h>
#include <mako/block.h>
#include <mako/coins.h>
#include <mako/consensus.h>
#include <mako/crypto/hash.h>
#include <mako/entry.h>
#include <mako/list.h>
#include <mako/map.h>
#include <mako/network.h>
#include <mako/tx.h>
#include <mako/util.h>
#include <mako/vector.h>
#include <node/chaindb.h>

#include "../bio.h"
#include "../impl.h"
#include "../internal.h"

/*
 * Options
 */

#undef USE_WORKER
#undef USE_CKPTR

#if defined(USE_CKPTR) && !defined(USE_WORKER)
#  error "invalid options"
#endif

#if defined(USE_WORKER) && defined(LSM_LEVELDB)
#  error "invalid options"
#endif

/*
 * Constants
 */

#define WRITE_FLAGS (BTC_O_RDWR | BTC_O_CREAT | BTC_O_APPEND)
#define READ_FLAGS (BTC_O_RDONLY | BTC_O_RANDOM)
#define MAX_FILE_SIZE (128 << 20)

/*
 * LSM Helpers
 */

static const char *
lsm_strerror(int code) {
  switch (code) {
#define X(c) case (c): return #c
    X(LSM_OK);
    X(LSM_ERROR);
    X(LSM_BUSY);
    X(LSM_NOMEM);
    X(LSM_READONLY);
    X(LSM_IOERR);
    X(LSM_CORRUPT);
    X(LSM_FULL);
    X(LSM_CANTOPEN);
    X(LSM_PROTOCOL);
    X(LSM_MISUSE);
    X(LSM_MISMATCH);
    X(LSM_IOERR_NOENT);
#undef X
  }
  return "LSM_UNKNOWN";
}

static int
lsm_csr_le(lsm_cursor *cur, const void *kp, int kn) {
  int cmp;

  if (!lsm_csr_valid(cur))
    return 0;

  CHECK(lsm_csr_cmp(cur, kp, kn, &cmp) == 0);

  return cmp <= 0;
}

static int
lsm_connect(lsm_db **lsm, const char *path) {
  lsm_db *db = NULL;
  int rc, op;

  rc = lsm_new(lsm_default_env(), &db);

  if (rc != LSM_OK)
    return rc;

#ifdef LSM_LEVELDB
  op = 64 * 1024; /* default = 8mb */
  rc = lsm_config(db, LSM_CONFIG_CACHE_SIZE, &op);

  if (rc != LSM_OK)
    goto done;

  op = 32 * 1024; /* default = 4mb */
  rc = lsm_config(db, LSM_CONFIG_BUFFER_SIZE, &op);

  if (rc != LSM_OK)
    goto done;
#endif

#ifdef USE_WORKER
  op = 4 * 1024; /* default = 1mb */
  rc = lsm_config(db, LSM_CONFIG_AUTOFLUSH, &op);

  if (rc != LSM_OK)
    goto done;

  op = 8 * 1024; /* default = 2mb */
  rc = lsm_config(db, LSM_CONFIG_AUTOCHECKPOINT, &op);

  if (rc != LSM_OK)
    goto done;

  op = 2; /* default = 4 */
  rc = lsm_config(db, LSM_CONFIG_AUTOMERGE, &op);

  if (rc != LSM_OK)
    goto done;
#endif

  op = 0; /* default = 1 */
  rc = lsm_config(db, LSM_CONFIG_MMAP, &op);

  if (rc != LSM_OK)
    goto done;

  op = 0; /* default = 1 */
  rc = lsm_config(db, LSM_CONFIG_MULTIPLE_PROCESSES, &op);

  if (rc != LSM_OK)
    goto done;

#ifdef USE_WORKER
  op = 0; /* default = 1 */
  rc = lsm_config(db, LSM_CONFIG_AUTOWORK, &op);

  if (rc != LSM_OK)
    goto done;
#endif

  rc = lsm_open(db, path);

  if (rc != LSM_OK)
    goto done;

  *lsm = db;

done:
  if (rc != LSM_OK)
    CHECK(lsm_close(db) == 0);

  return rc;
}

/*
 * LSM Worker
 */

#ifdef USE_WORKER
typedef struct lsm_worker_s {
  lsm_db *conn;
  btc_thread_t *thread;
  btc_cond_t *cond;
  btc_mutex_t *lock;
  int autockpt;
  int work;
  int stop;
  struct lsm_worker_s *ckptr;
} lsm_worker;

static void
lsm_worker_init(lsm_worker *w) {
  w->conn = NULL;
  w->thread = btc_thread_alloc();
  w->cond = btc_cond_create();
  w->lock = btc_mutex_create();
  w->autockpt = -1;
  w->work = 0;
  w->stop = 0;
  w->ckptr = NULL;
}

static void
lsm_worker_clear(lsm_worker *w) {
  btc_thread_free(w->thread);
  btc_cond_destroy(w->cond);
  btc_mutex_destroy(w->lock);
}

static int
lsm_worker_start(lsm_worker *w, const char *path, void (*start)(void *)) {
  int rc = lsm_connect(&w->conn, path);

  if (rc == LSM_OK) {
    w->autockpt = -1;

    CHECK(lsm_config(w->conn, LSM_CONFIG_AUTOCHECKPOINT, &w->autockpt) == 0);

    btc_thread_create(w->thread, start, w);
  }

  return rc;
}

static void
lsm_worker_stop(lsm_worker *w) {
  btc_mutex_lock(w->lock);

  w->stop = 1;

  btc_cond_signal(w->cond);
  btc_mutex_unlock(w->lock);

  btc_thread_join(w->thread);

  CHECK(lsm_close(w->conn) == 0);
}

static void
lsm_worker_signal(lsm_worker *w) {
  btc_mutex_lock(w->lock);

  w->work = 1;

  btc_cond_signal(w->cond);
  btc_mutex_unlock(w->lock);
}

static void
lsm_worker_ckpt(void *arg) {
  lsm_worker *w = (lsm_worker *)arg;
  int kb, rc;

  btc_mutex_lock(w->lock);

  while (!w->stop) {
    btc_mutex_unlock(w->lock);

    kb = 0;
    rc = lsm_info(w->conn, LSM_INFO_CHECKPOINT_SIZE, &kb);

    if (rc == LSM_OK && kb >= (w->autockpt / 4))
      rc = lsm_checkpoint(w->conn, 0);

    if (rc != LSM_OK && rc != LSM_BUSY)
      btc_abort(); /* LCOV_EXCL_LINE */

    btc_mutex_lock(w->lock);

    if (!w->stop && !w->work)
      btc_cond_wait(w->cond, w->lock);

    w->work = 0;
  }

  btc_mutex_unlock(w->lock);
}

static int
lsm_worker_barrier(lsm_worker *w, lsm_db *db) {
  int kb, rc;

  for (;;) {
    kb = 0;
    rc = lsm_info(db, LSM_INFO_CHECKPOINT_SIZE, &kb);

    if (rc != LSM_OK || kb < w->autockpt)
      break;

    lsm_worker_signal(w);

    btc_time_sleep(5);
  }

  return rc;
}

static void
lsm_worker_work(void *arg) {
  lsm_worker *w = (lsm_worker *)arg;
  int ckpt = (w->ckptr != NULL);
  int nwrite, rc;
  int val = 0;

  btc_mutex_lock(w->lock);

  if (ckpt)
    CHECK(lsm_config(w->conn, LSM_CONFIG_AUTOCHECKPOINT, &val) == 0);

  while (!w->stop) {
    btc_mutex_unlock(w->lock);

    do {
      if (ckpt)
        lsm_worker_barrier(w->ckptr, w->conn);

      nwrite = 0;
      rc = lsm_work(w->conn, 0, 256, &nwrite);

      if (rc != LSM_OK && rc != LSM_BUSY)
        btc_abort(); /* LCOV_EXCL_LINE */

      if (ckpt && nwrite > 0)
        lsm_worker_signal(w->ckptr);
    } while (nwrite > 0);

    btc_mutex_lock(w->lock);

    if (!w->stop && !w->work)
      btc_cond_wait(w->cond, w->lock);

    w->work = 0;
  }

  btc_mutex_unlock(w->lock);
}

static int
lsm_worker_wait(lsm_worker *w, lsm_db *db) {
  int rc, old, new;
  int limit = -1;

  rc = lsm_config(db, LSM_CONFIG_AUTOFLUSH, &limit);

  if (rc != LSM_OK)
    return rc;

  for (;;) {
    rc = lsm_info(db, LSM_INFO_TREE_SIZE, &old, &new);

    if (rc != LSM_OK)
      break;

    if (old == 0 || new < (limit / 2))
      break;

    lsm_worker_signal(w);

    btc_time_sleep(5);
  }

  return rc;
}

static void
lsm_worker_hook(lsm_db *db, void *arg) {
  lsm_worker *w = (lsm_worker *)arg;

  (void)db;

  lsm_worker_signal(w);
}
#endif /* USE_WORKER */

/*
 * Database Keys
 */

static const uint8_t meta_key[1] = {'R'};
static const uint8_t blockfile_key[1] = {'B'};
static const uint8_t undofile_key[1] = {'U'};

#define ENTRY_PREFIX 'e'
#define ENTRY_KEYLEN 33

static const uint8_t entry_min[ENTRY_KEYLEN] = {
  ENTRY_PREFIX,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t entry_max[ENTRY_KEYLEN] = {
  ENTRY_PREFIX,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

static void
entry_key(uint8_t *key, const uint8_t *hash) {
  key[0] = ENTRY_PREFIX;
  memcpy(key + 1, hash, 32);
}

#define TIP_PREFIX 'p'
#define TIP_KEYLEN 33

BTC_UNUSED static const uint8_t tip_min[TIP_KEYLEN] = {
  TIP_PREFIX,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

BTC_UNUSED static const uint8_t tip_max[TIP_KEYLEN] = {
  TIP_PREFIX,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

static void
tip_key(uint8_t *key, const uint8_t *hash) {
  key[0] = TIP_PREFIX;
  memcpy(key + 1, hash, 32);
}

#define FILE_PREFIX 'f'
#define FILE_KEYLEN 6

static const uint8_t file_min[FILE_KEYLEN] =
  {FILE_PREFIX, 0x00, 0x00, 0x00, 0x00, 0x00};

static const uint8_t file_max[FILE_KEYLEN] =
  {FILE_PREFIX, 0xff, 0xff, 0xff, 0xff, 0xff};

static void
file_key(uint8_t *key, uint8_t type, uint32_t id) {
  key[0] = FILE_PREFIX;
  key[1] = type;
  btc_write32be(key + 2, id);
}

#define COIN_PREFIX 'c'
#define COIN_KEYLEN 37

BTC_UNUSED static const uint8_t coin_min[COIN_KEYLEN] = {
  COIN_PREFIX,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00
};

BTC_UNUSED static const uint8_t coin_max[COIN_KEYLEN] = {
  COIN_PREFIX,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff
};

static void
coin_key(uint8_t *key, const uint8_t *hash, uint32_t index) {
  key[0] = COIN_PREFIX;
  memcpy(key + 1, hash, 32);
  btc_write32be(key + 33, index);
}

/*
 * Chain File
 */

#define BTC_CHAINFILE_SIZE 37

typedef struct btc_chainfile_s {
  int fd;
  uint8_t type;
  int32_t id;
  int32_t pos;
  int32_t items;
  int64_t min_time;
  int64_t max_time;
  int32_t min_height;
  int32_t max_height;
  struct btc_chainfile_s *prev;
  struct btc_chainfile_s *next;
} btc_chainfile_t;

DEFINE_SERIALIZABLE_OBJECT(btc_chainfile, SCOPE_STATIC)

static void
btc_chainfile_init(btc_chainfile_t *z) {
  z->fd = -1;
  z->type = 0;
  z->id = 0;
  z->pos = 0;
  z->items = 0;
  z->min_time = -1;
  z->max_time = -1;
  z->min_height = -1;
  z->max_height = -1;
  z->prev = NULL;
  z->next = NULL;
}

static void
btc_chainfile_clear(btc_chainfile_t *z) {
  btc_chainfile_init(z);
}

static void
btc_chainfile_copy(btc_chainfile_t *z, const btc_chainfile_t *x) {
  z->fd = -1;
  z->type = x->type;
  z->id = x->id;
  z->pos = x->pos;
  z->items = x->items;
  z->min_time = x->min_time;
  z->max_time = x->max_time;
  z->min_height = x->min_height;
  z->max_height = x->max_height;
  z->prev = NULL;
  z->next = NULL;
}

static size_t
btc_chainfile_size(const btc_chainfile_t *x) {
  (void)x;
  return BTC_CHAINFILE_SIZE;
}

static uint8_t *
btc_chainfile_write(uint8_t *zp, const btc_chainfile_t *x) {
  zp = btc_uint8_write(zp, x->type);
  zp = btc_int32_write(zp, x->id);
  zp = btc_int32_write(zp, x->pos);
  zp = btc_int32_write(zp, x->items);
  zp = btc_int64_write(zp, x->min_time);
  zp = btc_int64_write(zp, x->max_time);
  zp = btc_int32_write(zp, x->min_height);
  zp = btc_int32_write(zp, x->max_height);
  return zp;
}

static int
btc_chainfile_read(btc_chainfile_t *z, const uint8_t **xp, size_t *xn) {
  if (!btc_uint8_read(&z->type, xp, xn))
    return 0;

  if (!btc_int32_read(&z->id, xp, xn))
    return 0;

  if (!btc_int32_read(&z->pos, xp, xn))
    return 0;

  if (!btc_int32_read(&z->items, xp, xn))
    return 0;

  if (!btc_int64_read(&z->min_time, xp, xn))
    return 0;

  if (!btc_int64_read(&z->max_time, xp, xn))
    return 0;

  if (!btc_int32_read(&z->min_height, xp, xn))
    return 0;

  if (!btc_int32_read(&z->max_height, xp, xn))
    return 0;

  return 1;
}

static void
btc_chainfile_update(btc_chainfile_t *z, const btc_entry_t *entry) {
  z->items += 1;

  if (z->min_time == -1 || entry->header.time < z->min_time)
    z->min_time = entry->header.time;

  if (z->max_time == -1 || entry->header.time > z->max_time)
    z->max_time = entry->header.time;

  if (z->min_height == -1 || entry->height < z->min_height)
    z->min_height = entry->height;

  if (z->max_height == -1 || entry->height > z->max_height)
    z->max_height = entry->height;
}

/*
 * Chain Database
 */

struct btc_chaindb_s {
  const btc_network_t *network;
  char prefix[BTC_PATH_MAX - 26];
  unsigned int flags;
  lsm_db *lsm;
#ifdef USE_WORKER
  lsm_worker worker;
#endif
#ifdef USE_CKPTR
  lsm_worker ckptr;
#endif
  btc_hashmap_t *hashes;
  btc_vector_t heights;
  btc_entry_t *head;
  btc_entry_t *tail;
  struct btc_chainfiles_s {
    btc_chainfile_t *head;
    btc_chainfile_t *tail;
    size_t length;
  } files;
  btc_chainfile_t block;
  btc_chainfile_t undo;
  uint8_t *slab;
};

static void
btc_chaindb_path(btc_chaindb_t *db, char *path, int type, int id) {
  const char *tag = (type == 0 ? "blk" : "rev");

#if defined(_WIN32)
  sprintf(path, "%s\\blocks\\%s%.5d.dat", db->prefix, tag, id);
#else
  sprintf(path, "%s/blocks/%s%.5d.dat", db->prefix, tag, id);
#endif
}

static void
btc_chaindb_init(btc_chaindb_t *db, const btc_network_t *network) {
  memset(db, 0, sizeof(*db));

  db->network = network;
  db->prefix[0] = '/';
  db->hashes = btc_hashmap_create();
  db->flags = BTC_CHAIN_DEFAULT_FLAGS;

#ifdef USE_WORKER
  lsm_worker_init(&db->worker);
#endif

#ifdef USE_CKPTR
  lsm_worker_init(&db->ckptr);

  db->worker.ckptr = &db->ckptr;
#endif

  btc_vector_init(&db->heights);

  db->slab = (uint8_t *)btc_malloc(24 + BTC_MAX_RAW_BLOCK_SIZE);
}

static void
btc_chaindb_clear(btc_chaindb_t *db) {
  btc_hashmap_destroy(db->hashes);
  btc_vector_clear(&db->heights);
#ifdef USE_WORKER
  lsm_worker_clear(&db->worker);
#endif
#ifdef USE_CKPTR
  lsm_worker_clear(&db->ckptr);
#endif
  btc_free(db->slab);
  memset(db, 0, sizeof(*db));
}

btc_chaindb_t *
btc_chaindb_create(const btc_network_t *network) {
  btc_chaindb_t *db = (btc_chaindb_t *)btc_malloc(sizeof(btc_chaindb_t));
  btc_chaindb_init(db, network);
  return db;
}

void
btc_chaindb_destroy(btc_chaindb_t *db) {
  btc_chaindb_clear(db);
  btc_free(db);
}

static int
btc_chaindb_load_prefix(btc_chaindb_t *db, const char *prefix) {
  char path[BTC_PATH_MAX];

  if (!btc_path_resolve(db->prefix, sizeof(db->prefix), prefix, 0))
    return 0;

  if (!btc_fs_mkdirp(db->prefix, 0755))
    return 0;

  if (!btc_path_join(path, sizeof(path), db->prefix, "blocks", 0))
    return 0;

  if (!btc_fs_exists(path) && !btc_fs_mkdir(path, 0755))
    return 0;

  return 1;
}

static int
btc_chaindb_load_database(btc_chaindb_t *db) {
  char path[BTC_PATH_MAX];
  int rc;

  if (!btc_path_join(path, sizeof(path), db->prefix, "chain.dat", 0)) {
    fprintf(stderr, "lsm_open: path too long\n");
    return 0;
  }

  rc = lsm_connect(&db->lsm, path);

  if (rc != 0) {
    fprintf(stderr, "lsm_connect: %s\n", lsm_strerror(rc));
    return 0;
  }

#ifdef USE_CKPTR
  rc = lsm_worker_start(&db->ckptr, path, lsm_worker_ckpt);

  if (rc != 0)
    goto fail;
#endif

#ifdef USE_WORKER
  rc = lsm_worker_start(&db->worker, path, lsm_worker_work);

  if (rc != 0)
    goto fail;

  lsm_config_work_hook(db->lsm, lsm_worker_hook, &db->worker);
#endif

  return 1;
#ifdef USE_WORKER
fail:
  fprintf(stderr, "lsm_worker_start: %s\n", lsm_strerror(rc));

  CHECK(lsm_close(db->lsm) == 0);

  db->lsm = NULL;

  return 0;
#endif
}

static void
btc_chaindb_unload_database(btc_chaindb_t *db) {
#ifdef USE_WORKER
  lsm_worker_stop(&db->worker);
#endif

#ifdef USE_CKPTR
  lsm_worker_stop(&db->ckptr);
#endif

  CHECK(lsm_close(db->lsm) == 0);

  db->lsm = NULL;
}

static int
btc_chaindb_load_files(btc_chaindb_t *db) {
  char path[BTC_PATH_MAX];
  btc_chainfile_t *file;
  lsm_cursor *cur;
  const void *vp;
  int vn;

  CHECK(lsm_csr_open(db->lsm, &cur) == 0);

  /* Read best block file. */
  CHECK(lsm_csr_seek(cur, blockfile_key, 1, LSM_SEEK_EQ) == 0);

  if (lsm_csr_valid(cur)) {
    CHECK(lsm_csr_value(cur, &vp, &vn) == 0);
    CHECK(btc_chainfile_import(&db->block, vp, vn));
    CHECK(db->block.type == 0);
  } else {
    btc_chainfile_init(&db->block);
    db->block.type = 0;
  }

  /* Read best undo file. */
  CHECK(lsm_csr_seek(cur, undofile_key, 1, LSM_SEEK_EQ) == 0);

  if (lsm_csr_valid(cur)) {
    CHECK(lsm_csr_value(cur, &vp, &vn) == 0);
    CHECK(btc_chainfile_import(&db->undo, vp, vn));
    CHECK(db->undo.type == 1);
  } else {
    btc_chainfile_init(&db->undo);
    db->undo.type = 1;
  }

  /* Read file index and build vector. */
  CHECK(lsm_csr_seek(cur, file_min, sizeof(file_min), LSM_SEEK_GE) == 0);

  while (lsm_csr_le(cur, file_max, sizeof(file_max))) {
    file = btc_chainfile_create();

    CHECK(lsm_csr_value(cur, &vp, &vn) == 0);

    CHECK(btc_chainfile_import(file, vp, vn));

    btc_list_push(&db->files, file, btc_chainfile_t);

    CHECK(lsm_csr_next(cur) == 0);
  }

  CHECK(lsm_csr_close(cur) == 0);

  /* Open block file for writing. */
  btc_chaindb_path(db, path, 0, db->block.id);

  db->block.fd = btc_fs_open(path, WRITE_FLAGS, 0644);

  CHECK(db->block.fd != -1);

  /* Open undo file for writing. */
  btc_chaindb_path(db, path, 1, db->undo.id);

  db->undo.fd = btc_fs_open(path, WRITE_FLAGS, 0644);

  CHECK(db->undo.fd != -1);

  return 1;
}

static void
btc_chaindb_unload_files(btc_chaindb_t *db) {
  btc_chainfile_t *file, *next;

  btc_fs_fsync(db->block.fd);
  btc_fs_fsync(db->undo.fd);

  btc_fs_close(db->block.fd);
  btc_fs_close(db->undo.fd);

  for (file = db->files.head; file != NULL; file = next) {
    next = file->next;
    btc_chainfile_destroy(file);
  }

  btc_list_reset(&db->files);
}

static int
btc_chaindb_init_index(btc_chaindb_t *db) {
  btc_view_t *view = btc_view_create();
  btc_entry_t *entry = btc_entry_create();
  btc_block_t block;

  btc_block_init(&block);
  btc_block_import(&block, db->network->genesis.data,
                           db->network->genesis.length);

  btc_entry_set_block(entry, &block, NULL);

  CHECK(btc_chaindb_save(db, entry, &block, view));

  btc_block_clear(&block);
  btc_view_destroy(view);

  return 1;
}

static int
btc_chaindb_load_index(btc_chaindb_t *db) {
  btc_entry_t *entry, *tip;
  btc_entry_t *gen = NULL;
  btc_hashmapiter_t iter;
  uint8_t tip_hash[32];
  lsm_cursor *cur;
  const void *vp;
  int vn;

  CHECK(lsm_csr_open(db->lsm, &cur) == 0);

  /* Read tip hash. */
  {
    CHECK(lsm_csr_seek(cur, meta_key, 1, LSM_SEEK_EQ) == 0);

    if (!lsm_csr_valid(cur)) {
      CHECK(lsm_csr_close(cur) == 0);
      return btc_chaindb_init_index(db);
    }

    CHECK(lsm_csr_value(cur, &vp, &vn) == 0);
    CHECK(vn == 32);

    memcpy(tip_hash, vp, 32);
  }

  /* Read block index and create hash->entry map. */
  CHECK(lsm_csr_seek(cur, entry_min, sizeof(entry_min), LSM_SEEK_GE) == 0);

  while (lsm_csr_le(cur, entry_max, sizeof(entry_max))) {
    entry = btc_entry_create();

    CHECK(lsm_csr_value(cur, &vp, &vn) == 0);

    CHECK(btc_entry_import(entry, vp, vn));
    CHECK(btc_hashmap_put(db->hashes, entry->hash, entry));

    CHECK(lsm_csr_next(cur) == 0);
  }

  CHECK(lsm_csr_close(cur) == 0);

  /* Create `prev` links and retrieve genesis block. */
  btc_hashmap_iterate(&iter, db->hashes);

  while (btc_hashmap_next(&iter)) {
    entry = iter.val;

    if (entry->height == 0) {
      gen = entry;
      continue;
    }

    entry->prev = btc_hashmap_get(db->hashes, entry->header.prev_block);

    CHECK(entry->prev != NULL);
  }

  CHECK(gen != NULL);

  /* Retrieve tip. */
  tip = btc_hashmap_get(db->hashes, tip_hash);

  CHECK(tip != NULL);

  /* Create height->entry vector. */
  btc_vector_grow(&db->heights, (btc_hashmap_size(db->hashes) * 3) / 2);
  btc_vector_resize(&db->heights, tip->height + 1);

  /* Populate height vector and create `next` links. */
  entry = tip;

  do {
    CHECK((size_t)entry->height < db->heights.length);

    db->heights.items[entry->height] = entry;

    if (entry->prev != NULL)
      entry->prev->next = entry;

    entry = entry->prev;
  } while (entry != NULL);

  db->head = gen;
  db->tail = tip;

  return 1;
}

static void
btc_chaindb_unload_index(btc_chaindb_t *db) {
  btc_hashmapiter_t iter;

  btc_hashmap_iterate(&iter, db->hashes);

  while (btc_hashmap_next(&iter))
    btc_entry_destroy(iter.val);

  btc_hashmap_reset(db->hashes);
  btc_vector_clear(&db->heights);

  db->head = NULL;
  db->tail = NULL;
}

int
btc_chaindb_open(btc_chaindb_t *db,
                 const char *prefix,
                 unsigned int flags) {
  db->flags = flags;

  if (!btc_chaindb_load_prefix(db, prefix))
    return 0;

  if (!btc_chaindb_load_database(db))
    return 0;

  if (!btc_chaindb_load_files(db))
    return 0;

  if (!btc_chaindb_load_index(db))
    return 0;

  return 1;
}

void
btc_chaindb_close(btc_chaindb_t *db) {
  btc_chaindb_unload_index(db);
  btc_chaindb_unload_files(db);
  btc_chaindb_unload_database(db);
}

static btc_coin_t *
read_coin(const btc_outpoint_t *prevout, void *arg1, void *arg2) {
  btc_chaindb_t *db = (btc_chaindb_t *)arg1;
  lsm_cursor *cur = (lsm_cursor *)arg2;
  uint8_t key[COIN_KEYLEN];
  btc_coin_t *coin;
  const void *vp;
  int rc, vn;

  (void)db;

  coin_key(key, prevout->hash, prevout->index);

  rc = lsm_csr_seek(cur, key, sizeof(key), LSM_SEEK_EQ);

  if (rc != 0) {
    fprintf(stderr, "lsm_csr_seek: %s\n", lsm_strerror(rc));
    return NULL;
  }

  if (!lsm_csr_valid(cur))
    return NULL;

  coin = btc_coin_create();

  CHECK(lsm_csr_value(cur, &vp, &vn) == 0);
  CHECK(btc_coin_import(coin, vp, vn));

  return coin;
}

int
btc_chaindb_spend(btc_chaindb_t *db,
                  btc_view_t *view,
                  const btc_tx_t *tx) {
  lsm_cursor *cur;
  int rc;

  rc = lsm_csr_open(db->lsm, &cur);

  if (rc != 0) {
    fprintf(stderr, "lsm_csr_open: %s\n", lsm_strerror(rc));
    return 0;
  }

  rc = btc_view_spend(view, tx, read_coin, db, cur);

  CHECK(lsm_csr_close(cur) == 0);

  return rc;
}

int
btc_chaindb_fill(btc_chaindb_t *db,
                 btc_view_t *view,
                 const btc_tx_t *tx) {
  lsm_cursor *cur;
  int rc;

  rc = lsm_csr_open(db->lsm, &cur);

  if (rc != 0) {
    fprintf(stderr, "lsm_csr_open: %s\n", lsm_strerror(rc));
    return 0;
  }

  rc = btc_view_fill(view, tx, read_coin, db, cur);

  CHECK(lsm_csr_close(cur) == 0);

  return rc;
}

static int
btc_chaindb_save_view(btc_chaindb_t *db, const btc_view_t *view) {
  uint8_t key[COIN_KEYLEN];
  uint8_t *val = db->slab;
  const btc_coin_t *coin;
  btc_viewiter_t iter;
  size_t len;
  int rc;

  btc_view_iterate(&iter, view);

  while (btc_view_next(&coin, &iter)) {
    coin_key(key, iter.hash, iter.index);

    if (coin->spent) {
      rc = lsm_delete(db->lsm, key, sizeof(key));
    } else {
      len = btc_coin_export(val, coin);
      rc = lsm_insert(db->lsm, key, sizeof(key), val, len);
    }

    if (rc != 0) {
      fprintf(stderr, "lsm_insert: %s\n", lsm_strerror(rc));
      return 0;
    }
  }

  return 1;
}

static int
btc_chaindb_read(btc_chaindb_t *db,
                 uint8_t **raw,
                 size_t *len,
                 const btc_chainfile_t *file,
                 int id,
                 int pos) {
  char path[BTC_PATH_MAX];
  uint8_t *data = NULL;
  uint8_t tmp[4];
  size_t size;
  int ret = 0;
  int fd;

  if (id == file->id) {
    fd = file->fd;
  } else {
    btc_chaindb_path(db, path, file->type, id);

    fd = btc_fs_open(path, READ_FLAGS, 0);

    if (fd == -1)
      return 0;
  }

  if (!btc_fs_pread(fd, tmp, 4, pos + 16))
    goto fail;

  size = 24 + btc_read32le(tmp);
  data = (uint8_t *)malloc(size);

  if (data == NULL)
    goto fail;

  if (!btc_fs_pread(fd, data, size, pos))
    goto fail;

  *raw = data;
  *len = size;

  data = NULL;
  ret = 1;
fail:
  if (data != NULL)
    free(data);

  if (fd != file->fd)
    btc_fs_close(fd);

  return ret;
}

static btc_block_t *
btc_chaindb_read_block(btc_chaindb_t *db, const btc_entry_t *entry) {
  btc_block_t *block;
  uint8_t *buf;
  size_t len;

  if (entry->block_pos == -1)
    return NULL;

  if (!btc_chaindb_read(db, &buf, &len, &db->block, entry->block_file,
                                                    entry->block_pos)) {
    return NULL;
  }

  block = btc_block_decode(buf + 24, len - 24);

  free(buf);

  return block;
}

static btc_undo_t *
btc_chaindb_read_undo(btc_chaindb_t *db, const btc_entry_t *entry) {
  btc_undo_t *undo;
  uint8_t *buf;
  size_t len;

  if (entry->undo_pos == -1)
    return btc_undo_create();

  if (!btc_chaindb_read(db, &buf, &len, &db->undo, entry->undo_file,
                                                   entry->undo_pos)) {
    return NULL;
  }

  undo = btc_undo_decode(buf + 24, len - 24);

  free(buf);

  return undo;
}

static int
should_sync(const btc_entry_t *entry) {
  if (entry->header.time >= btc_now() - 24 * 60 * 60)
    return 1;

  if ((entry->height % 20000) == 0)
    return 1;

  return 0;
}

static int
btc_chaindb_alloc(btc_chaindb_t *db, btc_chainfile_t *file, size_t len) {
  uint8_t raw[BTC_CHAINFILE_SIZE];
  uint8_t key[FILE_KEYLEN];
  char path[BTC_PATH_MAX];
  int fd;

  if (file->pos + len <= MAX_FILE_SIZE)
    return 1;

  file_key(key, file->type, file->id);

  btc_chainfile_export(raw, file);

  if (lsm_insert(db->lsm, key, sizeof(key), raw, sizeof(raw)) != 0)
    return 0;

  btc_chaindb_path(db, path, file->type, file->id + 1);

  fd = btc_fs_open(path, WRITE_FLAGS, 0644);

  if (fd == -1)
    return 0;

  btc_fs_fsync(file->fd);
  btc_fs_close(file->fd);

  btc_list_push(&db->files, btc_chainfile_clone(file),
                            btc_chainfile_t);

  file->fd = fd;
  file->id++;
  file->pos = 0;
  file->items = 0;
  file->min_time = -1;
  file->max_time = -1;
  file->min_height = -1;
  file->max_height = -1;

  return 1;
}

static int
btc_chaindb_write_block(btc_chaindb_t *db,
                        btc_entry_t *entry,
                        const btc_block_t *block) {
  uint8_t raw[BTC_CHAINFILE_SIZE];
  uint8_t hash[32];
  size_t len;

  len = btc_block_export(db->slab + 24, block);

  btc_hash256(hash, db->slab + 24, len);

  /* Store in network format. */
  btc_uint32_write(db->slab +  0, db->network->magic);
  btc_uint32_write(db->slab +  4, 0x636f6c62);
  btc_uint32_write(db->slab +  8, 0x0000006b);
  btc_uint32_write(db->slab + 12, 0x00000000);
  btc_uint32_write(db->slab + 16, len);

  btc_raw_write(db->slab + 20, hash, 4);

  len += 24;

  if (!btc_chaindb_alloc(db, &db->block, len))
    return 0;

  if (!btc_fs_write(db->block.fd, db->slab, len))
    return 0;

  if (should_sync(entry))
    btc_fs_fsync(db->block.fd);

  entry->block_file = db->block.id;
  entry->block_pos = db->block.pos;

  db->block.pos += len;

  btc_chainfile_update(&db->block, entry);

  btc_chainfile_export(raw, &db->block);

  if (lsm_insert(db->lsm, blockfile_key, 1, raw, sizeof(raw)) != 0)
    return 0;

  return 1;
}

static int
btc_chaindb_write_undo(btc_chaindb_t *db,
                       btc_entry_t *entry,
                       const btc_undo_t *undo) {
  size_t len = btc_undo_size(undo);
  uint8_t raw[BTC_CHAINFILE_SIZE];
  uint8_t *buf = db->slab;
  uint8_t hash[32];
  int ret = 0;

  if (len > BTC_MAX_RAW_BLOCK_SIZE)
    buf = (uint8_t *)btc_malloc(24 + len);

  len = btc_undo_export(buf + 24, undo);

  btc_hash256(hash, buf + 24, len);

  btc_uint32_write(buf +  0, db->network->magic);
  btc_uint32_write(buf +  4, 0x00000000);
  btc_uint32_write(buf +  8, 0x00000000);
  btc_uint32_write(buf + 12, 0x00000000);
  btc_uint32_write(buf + 16, len);

  btc_raw_write(buf + 20, hash, 4);

  len += 24;

  if (!btc_chaindb_alloc(db, &db->undo, len))
    goto fail;

  if (!btc_fs_write(db->undo.fd, buf, len))
    goto fail;

  if (should_sync(entry))
    btc_fs_fsync(db->undo.fd);

  entry->undo_file = db->undo.id;
  entry->undo_pos = db->undo.pos;

  db->undo.pos += len;

  btc_chainfile_update(&db->undo, entry);

  btc_chainfile_export(raw, &db->undo);

  if (lsm_insert(db->lsm, undofile_key, 1, raw, sizeof(raw)) != 0)
    goto fail;

  ret = 1;
fail:
  if (buf != db->slab)
    btc_free(buf);

  return ret;
}

static int
btc_chaindb_prune_files(btc_chaindb_t *db, const btc_entry_t *entry) {
  btc_chainfile_t *file, *next;
  uint8_t key[FILE_KEYLEN];
  char path[BTC_PATH_MAX];
  int32_t target;

  if (!(db->flags & BTC_CHAIN_PRUNE))
    return 1;

  if (entry->height < db->network->block.keep_blocks)
    return 1;

  target = entry->height - db->network->block.keep_blocks;

  if (target <= db->network->block.prune_after_height)
    return 1;

  for (file = db->files.head; file != NULL; file = file->next) {
    if (file->max_height >= target)
      continue;

    file_key(key, file->type, file->id);

    if (lsm_delete(db->lsm, key, sizeof(key)) != 0)
      return 0;
  }

  for (file = db->files.head; file != NULL; file = next) {
    next = file->next;

    if (file->max_height >= target)
      continue;

    btc_chaindb_path(db, path, file->type, file->id);

    btc_fs_unlink(path);

    btc_list_remove(&db->files, file, btc_chainfile_t);

    btc_chainfile_destroy(file);
  }

  return 1;
}

static int
btc_chaindb_connect_block(btc_chaindb_t *db,
                          btc_entry_t *entry,
                          const btc_block_t *block,
                          const btc_view_t *view) {
  const btc_undo_t *undo;

  (void)block;

  /* Genesis block's coinbase is unspendable. */
  if (entry->height == 0)
    return 1;

  /* Commit new coin state. */
  if (!btc_chaindb_save_view(db, view))
    return 0;

  /* Write undo coins (if there are any). */
  undo = btc_view_undo(view);

  if (undo->length != 0 && entry->undo_pos == -1) {
    if (!btc_chaindb_write_undo(db, entry, undo))
      return 0;
  }

  /* Prune height-288 if pruning is enabled. */
  return btc_chaindb_prune_files(db, entry);
}

static btc_view_t *
btc_chaindb_disconnect_block(btc_chaindb_t *db,
                             const btc_entry_t *entry,
                             const btc_block_t *block) {
  btc_undo_t *undo = btc_chaindb_read_undo(db, entry);
  const btc_input_t *input;
  const btc_tx_t *tx;
  btc_coin_t *coin;
  btc_view_t *view;
  size_t i, j;

  if (undo == NULL)
    return NULL;

  view = btc_view_create();

  /* Disconnect all transactions. */
  for (i = block->txs.length - 1; i != (size_t)-1; i--) {
    tx = block->txs.items[i];

    for (j = tx->inputs.length - 1; j != (size_t)-1; j--) {
      input = tx->inputs.items[j];
      coin = btc_undo_pop(undo);

      btc_view_put(view, &input->prevout, coin);
    }

    /* Remove any created coins. */
    btc_view_add(view, tx, entry->height, 1);
  }

  /* Undo coins should be empty. */
  CHECK(undo->length == 0);

  btc_undo_destroy(undo);

  /* Commit new coin state. */
  if (!btc_chaindb_save_view(db, view)) {
    btc_view_destroy(view);
    return NULL;
  }

  return view;
}

static int
btc_chaindb_save_block(btc_chaindb_t *db,
                       btc_entry_t *entry,
                       const btc_block_t *block,
                       const btc_view_t *view) {
  /* Write actual block data. */
  if (entry->block_pos == -1) {
    if (!btc_chaindb_write_block(db, entry, block))
      return 0;
  }

  if (view == NULL)
    return 1;

  return btc_chaindb_connect_block(db, entry, block, view);
}

int
btc_chaindb_save(btc_chaindb_t *db,
                 btc_entry_t *entry,
                 const btc_block_t *block,
                 const btc_view_t *view) {
  uint8_t raw[BTC_ENTRY_SIZE];
  uint8_t key[ENTRY_KEYLEN];

  /* Sanity checks. */
  CHECK(entry->prev != NULL || entry->height == 0);
  CHECK(entry->next == NULL);

#ifdef USE_WORKER
  /* Wait for worker. */
  if (lsm_worker_wait(&db->worker, db->lsm) != 0)
    return 0;
#endif

  /* Begin transaction. */
  if (lsm_begin(db->lsm, 1) != 0)
    return 0;

  /* Connect block and save data. */
  if (!btc_chaindb_save_block(db, entry, block, view))
    goto fail;

  /* Write entry data. */
  entry_key(key, entry->hash);

  btc_entry_export(raw, entry);

  if (lsm_insert(db->lsm, key, sizeof(key), raw, sizeof(raw)) != 0)
    goto fail;

  /* Clear old tip. */
  if (entry->height != 0) {
    tip_key(key, entry->header.prev_block);

    if (lsm_delete(db->lsm, key, sizeof(key)) != 0)
      goto fail;
  }

  /* Write new tip. */
  tip_key(key, entry->hash);

  if (lsm_insert(db->lsm, key, sizeof(key), raw, 1) != 0)
    goto fail;

  /* Write state (main chain only). */
  if (view != NULL) {
    /* Commit new chain state. */
    if (lsm_insert(db->lsm, meta_key, 1, entry->hash, 32) != 0)
      goto fail;
  }

  /* Commit transaction. */
  if (lsm_commit(db->lsm, 0) != 0)
    goto fail;

  /* Update hashes. */
  CHECK(btc_hashmap_put(db->hashes, entry->hash, entry));

  /* Main-chain-only stuff. */
  if (view != NULL) {
    /* Set next pointer. */
    if (entry->prev != NULL)
      entry->prev->next = entry;

    /* Update heights. */
    CHECK(db->heights.length == (size_t)entry->height);
    btc_vector_push(&db->heights, entry);

    /* Update tip. */
    if (entry->height == 0)
      db->head = entry;

    db->tail = entry;
  }

  return 1;
fail:
  CHECK(lsm_rollback(db->lsm, 0) == 0);
  return 0;
}

int
btc_chaindb_reconnect(btc_chaindb_t *db,
                      btc_entry_t *entry,
                      const btc_block_t *block,
                      const btc_view_t *view) {
  uint8_t raw[BTC_ENTRY_SIZE];
  uint8_t key[ENTRY_KEYLEN];

#ifdef USE_WORKER
  /* Wait for worker. */
  if (lsm_worker_wait(&db->worker, db->lsm) != 0)
    return 0;
#endif

  /* Begin transaction. */
  if (lsm_begin(db->lsm, 1) != 0)
    return 0;

  /* Connect inputs. */
  if (!btc_chaindb_connect_block(db, entry, block, view))
    goto fail;

  /* Re-write entry data (we may have updated the undo pos). */
  entry_key(key, entry->hash);

  btc_entry_export(raw, entry);

  if (lsm_insert(db->lsm, key, sizeof(key), raw, sizeof(raw)) != 0)
    goto fail;

  /* Commit new chain state. */
  if (lsm_insert(db->lsm, meta_key, 1, entry->hash, 32) != 0)
    goto fail;

  /* Commit transaction. */
  if (lsm_commit(db->lsm, 0) != 0)
    goto fail;

  /* Set next pointer. */
  CHECK(entry->prev != NULL);
  CHECK(entry->next == NULL);
  entry->prev->next = entry;

  /* Update heights. */
  CHECK(db->heights.length == (size_t)entry->height);
  btc_vector_push(&db->heights, entry);

  /* Update tip. */
  db->tail = entry;

  return 1;
fail:
  CHECK(lsm_rollback(db->lsm, 0) == 0);
  return 0;
}

btc_view_t *
btc_chaindb_disconnect(btc_chaindb_t *db,
                       btc_entry_t *entry,
                       const btc_block_t *block) {
  btc_view_t *view;

#ifdef USE_WORKER
  /* Wait for worker. */
  if (lsm_worker_wait(&db->worker, db->lsm) != 0)
    return 0;
#endif

  /* Begin transaction. */
  if (lsm_begin(db->lsm, 1) != 0)
    return NULL;

  /* Disconnect inputs. */
  view = btc_chaindb_disconnect_block(db, entry, block);

  if (view == NULL)
    goto fail;

  /* Revert chain state to previous tip. */
  if (lsm_insert(db->lsm, meta_key, 1, entry->header.prev_block, 32) != 0)
    goto fail;

  /* Commit transaction. */
  if (lsm_commit(db->lsm, 0) != 0)
    goto fail;

  /* Set next pointer. */
  CHECK(entry->prev != NULL);
  CHECK(entry->next == NULL);
  entry->prev->next = NULL;

  /* Update heights. */
  CHECK((btc_entry_t *)btc_vector_pop(&db->heights) == entry);

  /* Revert tip. */
  db->tail = entry->prev;

  return view;
fail:
  if (view != NULL)
    btc_view_destroy(view);

  CHECK(lsm_rollback(db->lsm, 0) == 0);

  return NULL;
}

const btc_entry_t *
btc_chaindb_head(btc_chaindb_t *db) {
  return db->head;
}

const btc_entry_t *
btc_chaindb_tail(btc_chaindb_t *db) {
  return db->tail;
}

int32_t
btc_chaindb_height(btc_chaindb_t *db) {
  return db->tail->height;
}

const btc_entry_t *
btc_chaindb_by_hash(btc_chaindb_t *db, const uint8_t *hash) {
  return btc_hashmap_get(db->hashes, hash);
}

const btc_entry_t *
btc_chaindb_by_height(btc_chaindb_t *db, int32_t height) {
  if ((size_t)height >= db->heights.length)
    return NULL;

  return (btc_entry_t *)db->heights.items[height];
}

int
btc_chaindb_is_main(btc_chaindb_t *db, const btc_entry_t *entry) {
  if ((size_t)entry->height >= db->heights.length)
    return 0;

  return (btc_entry_t *)db->heights.items[entry->height] == entry;
}

int
btc_chaindb_has_coins(btc_chaindb_t *db, const btc_tx_t *tx) {
  uint8_t min[COIN_KEYLEN];
  uint8_t max[COIN_KEYLEN];
  lsm_cursor *cur;
  int ret;

  coin_key(min, tx->hash, 0);
  coin_key(max, tx->hash, UINT32_MAX);

  CHECK(lsm_csr_open(db->lsm, &cur) == 0);
  CHECK(lsm_csr_seek(cur, min, sizeof(min), LSM_SEEK_GE) == 0);

  ret = lsm_csr_le(cur, max, sizeof(max));

  CHECK(lsm_csr_close(cur) == 0);

  return ret;
}

btc_block_t *
btc_chaindb_get_block(btc_chaindb_t *db, const btc_entry_t *entry) {
  return btc_chaindb_read_block(db, entry);
}

int
btc_chaindb_get_raw_block(btc_chaindb_t *db,
                          uint8_t **data,
                          size_t *length,
                          const btc_entry_t *entry) {
  if (entry->block_pos == -1)
    return 0;

  return btc_chaindb_read(db, data, length, &db->block, entry->block_file,
                                                        entry->block_pos);

}
