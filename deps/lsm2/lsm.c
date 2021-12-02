/*!
 * lsm.c - leveldb wrapper for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <leveldb/c.h>
#include "lsm.h"

/*
 * Macros
 */

#define CHECK(x) if (!(x)) abort()

/*
 * Types
 */

struct lsm_db {
  leveldb_options_t *options;
  leveldb_readoptions_t *read_options;
  leveldb_writeoptions_t *write_options;
  leveldb_readoptions_t *iter_options;
  leveldb_t *level;
  leveldb_writebatch_t *batch;
};

struct lsm_cursor {
  leveldb_iterator_t *it;
  int invalid;
};

/*
 * Database
 */

int
lsm_new(lsm_env *env, lsm_db **lsm) {
  leveldb_options_t *options;
  leveldb_cache_t *cache;
  leveldb_filterpolicy_t *bloom;
  leveldb_readoptions_t *read_options;
  leveldb_writeoptions_t *write_options;
  leveldb_readoptions_t *iter_options;
  lsm_db *db;

  if (env != NULL)
    return LSM_MISUSE;

  db = (lsm_db *)malloc(sizeof(lsm_db));

  if (db == NULL)
    return LSM_NOMEM;

  options = leveldb_options_create();
  cache = leveldb_cache_create_lru(8 << 20);
  bloom = leveldb_filterpolicy_create_bloom(10);
  read_options = leveldb_readoptions_create();
  write_options = leveldb_writeoptions_create();
  iter_options = leveldb_readoptions_create();

  leveldb_options_set_create_if_missing(options, 1);
  leveldb_options_set_error_if_exists(options, 0);
  leveldb_options_set_compression(options, leveldb_no_compression);
  leveldb_options_set_cache(options, cache);
  leveldb_options_set_write_buffer_size(options, 4 << 20);
  leveldb_options_set_block_size(options, 4096);
  leveldb_options_set_max_open_files(options, 64);
  leveldb_options_set_block_restart_interval(options, 16);
  leveldb_options_set_max_file_size(options, 2 << 20);
  leveldb_options_set_filter_policy(options, bloom);
  leveldb_options_set_paranoid_checks(options, 0);

  leveldb_readoptions_set_verify_checksums(read_options, 0);
  leveldb_readoptions_set_fill_cache(read_options, 1);

  leveldb_writeoptions_set_sync(write_options, 0);

  leveldb_readoptions_set_verify_checksums(iter_options, 0);
  leveldb_readoptions_set_fill_cache(iter_options, 0);

  db->options = options;
  db->read_options = read_options;
  db->write_options = write_options;
  db->iter_options = iter_options;
  db->level = NULL;
  db->batch = NULL;

  *lsm = db;

  return LSM_OK;
}

int
lsm_open(lsm_db *db, const char *file) {
  char *err = NULL;

  db->level = leveldb_open(db->options, file, &err);

  if (err != NULL) {
    CHECK(db->level == NULL);

    fprintf(stderr, "leveldb_open: %s\n", err);

    free(err);

    return LSM_ERROR;
  }

  CHECK(db->level != NULL);

  return LSM_OK;
}

int
lsm_close(lsm_db *db) {
  if (db->batch != NULL) {
    leveldb_writebatch_destroy(db->batch);
    db->batch = NULL;
  }

  if (db->level != NULL) {
    leveldb_close(db->level);
    db->level = NULL;
  }

  leveldb_options_destroy(db->options);
  leveldb_readoptions_destroy(db->read_options);
  leveldb_writeoptions_destroy(db->write_options);
  leveldb_readoptions_destroy(db->iter_options);

  free(db);

  return LSM_OK;
}

int
lsm_flush(lsm_db *db) {
  CHECK(db != NULL);
  return LSM_OK;
}

int
lsm_work(lsm_db *db, int merge, int kb, int *nwrite) {
  CHECK(db != NULL);

  if (nwrite != NULL)
    *nwrite = 0;

  return LSM_OK;
}

int
lsm_checkpoint(lsm_db *db, int *kb) {
  CHECK(db != NULL);

  if (kb != NULL)
    *kb = 0;

  return LSM_OK;
}

/*
 * Config
 */

int
lsm_config(lsm_db *db, int param, ...) {
  int rc = LSM_OK;
  va_list ap;

  va_start(ap, param);

  switch (param) {
    case LSM_CONFIG_AUTOFLUSH: {
      int *ptr = va_arg(ap, int *);
      int val = *ptr;

      if (db->level == NULL && val >= 0 && val <= (1024 * 1024))
        leveldb_options_set_write_buffer_size(db->options, val * 1024);
      else
        *ptr = 0;

      break;
    }

    case LSM_CONFIG_AUTOWORK: {
      int *ptr = va_arg(ap, int *);
      if (*ptr < 0)
        *ptr = 0;
      break;
    }

    case LSM_CONFIG_AUTOCHECKPOINT: {
      int *ptr = va_arg(ap, int *);
      if (*ptr < 0)
        *ptr = 0;
      break;
    }

    case LSM_CONFIG_PAGE_SIZE: {
      int *ptr = va_arg(ap, int *);
      if (*ptr < 0)
        *ptr = 0;
      break;
    }

    case LSM_CONFIG_BLOCK_SIZE: {
      int *ptr = va_arg(ap, int *);
      int val = *ptr;

      if (db->level != NULL) {
        *ptr = 0;
      } else {
        if (val >= 64 && val <= 65536 && (val & (val - 1)) == 0)
          leveldb_options_set_block_size(db->options, val * 1024);
        else
          *ptr = 0;
      }

      break;
    }

    case LSM_CONFIG_SAFETY: {
      int *ptr = va_arg(ap, int *);
      int val = *ptr;

      if (val >= 0) {
        leveldb_readoptions_set_verify_checksums(db->read_options, 0);

        if (db->level == NULL)
          leveldb_options_set_paranoid_checks(db->options, 0);

        if (val >= 1)
          leveldb_readoptions_set_verify_checksums(db->read_options, 1);

        if (val >= 2 && db->level == NULL)
          leveldb_options_set_paranoid_checks(db->options, 1);
      } else {
        *ptr = 0;
      }

      break;
    }

    case LSM_CONFIG_MMAP: {
      int *ptr = va_arg(ap, int *);
      if (*ptr < 0)
        *ptr = 0;
      break;
    }

    case LSM_CONFIG_USE_LOG: {
      int *ptr = va_arg(ap, int *);
      if (*ptr < 0)
        *ptr = 0;
      break;
    }

    case LSM_CONFIG_AUTOMERGE: {
      int *ptr = va_arg(ap, int *);
      if (*ptr < 2)
        *ptr = 2;
      break;
    }

    case LSM_CONFIG_MAX_FREELIST: {
      int *ptr = va_arg(ap, int *);
      if (*ptr < 2)
        *ptr = 2;
      break;
    }

    case LSM_CONFIG_MULTIPLE_PROCESSES: {
      int *ptr = va_arg(ap, int *);
      if (*ptr < 0)
        *ptr = 0;
      break;
    }

    case LSM_CONFIG_READONLY: {
      int *ptr = va_arg(ap, int *);
      if (*ptr < 0)
        *ptr = 0;
      break;
    }

    case LSM_CONFIG_SET_COMPRESSION: {
      rc = LSM_MISUSE;
      break;
    }

    case LSM_CONFIG_SET_COMPRESSION_FACTORY: {
      rc = LSM_MISUSE;
      break;
    }

    case LSM_CONFIG_GET_COMPRESSION: {
      rc = LSM_MISUSE;
      break;
    }

    default: {
      rc = LSM_MISUSE;
      break;
    }
  }

  va_end(ap);

  return rc;
}

void
lsm_config_log(lsm_db *db, void (*cb)(void *, int, const char *), void *arg) {
  CHECK(db != NULL);
  CHECK(cb != NULL);
  (void)arg;
}

void
lsm_config_work_hook(lsm_db *db, void (*cb)(lsm_db *, void *), void *arg) {
  CHECK(db != NULL);
  CHECK(cb != NULL);
  (void)arg;
}

/*
 * Info
 */

int
lsm_info(lsm_db *db, int param, ...) {
  int rc = LSM_OK;
  va_list ap;

  va_start(ap, param);

  switch (param) {
    case LSM_INFO_NWRITE: {
      int *ptr = va_arg(ap, int *);
      *ptr = 0;
      break;
    }

    case LSM_INFO_NREAD: {
      int *ptr = va_arg(ap, int *);
      *ptr = 0;
      break;
    }

    case LSM_INFO_DB_STRUCTURE: {
      char **ptr = va_arg(ap, char **);
      *ptr = NULL;
      break;
    }

    case LSM_INFO_ARRAY_STRUCTURE: {
      lsm_i64 pgno = va_arg(ap, lsm_i64);
      char **ptr = va_arg(ap, char **);
      (void)pgno;
      *ptr = NULL;
      break;
    }

    case LSM_INFO_ARRAY_PAGES: {
      lsm_i64 pgno = va_arg(ap, lsm_i64);
      char **ptr = va_arg(ap, char **);
      (void)pgno;
      *ptr = NULL;
      break;
    }

    case LSM_INFO_PAGE_HEX_DUMP:
    case LSM_INFO_PAGE_ASCII_DUMP: {
      lsm_i64 pgno = va_arg(ap, lsm_i64);
      char **ptr = va_arg(ap, char **);
      (void)pgno;
      *ptr = NULL;
      break;
    }

    case LSM_INFO_LOG_STRUCTURE: {
      char **ptr = va_arg(ap, char **);
      *ptr = NULL;
      break;
    }

    case LSM_INFO_FREELIST: {
      char **ptr = va_arg(ap, char **);
      *ptr = NULL;
      break;
    }

    case LSM_INFO_CHECKPOINT_SIZE: {
      int *ptr = va_arg(ap, int *);
      *ptr = 0;
      break;
    }

    case LSM_INFO_TREE_SIZE: {
      int *pold = va_arg(ap, int *);
      int *pnew = va_arg(ap, int *);
      *pold = 0;
      *pnew = 0;
      break;
    }

    case LSM_INFO_COMPRESSION_ID: {
      unsigned int *ptr = va_arg(ap, unsigned int *);
      *ptr = 0;
      break;
    }

    default: {
      rc = LSM_MISUSE;
      break;
    }
  }

  va_end(ap);

  return rc;
}

/*
 * Meta
 */

lsm_env *
lsm_get_env(lsm_db *db) {
  (void)db;
  return NULL;
}

lsm_env *
lsm_default_env(void) {
  return NULL;
}

int
lsm_get_user_version(lsm_db *db, unsigned int *ptr) {
  CHECK(db != NULL);
  *ptr = 0;
  return LSM_OK;
}

int
lsm_set_user_version(lsm_db *db, unsigned int val) {
  CHECK(db != NULL);

  if (val != 0)
    return LSM_MISUSE;

  return LSM_OK;
}

/*
 * Comparator
 */

static int
iter_compare(leveldb_iterator_t *it, const void *yp, int yn) {
  size_t xs;
  const void *xp = leveldb_iter_key(it, &xs);
  int xn = xs;
  int min = xn < yn ? xn : yn;
  int cmp = 0;

  if (min != 0)
    cmp = memcmp(xp, yp, min);

  if (cmp == 0)
    cmp = xn - yn;

  return cmp;
}

/*
 * Transaction
 */

int
lsm_begin(lsm_db *db, int level) {
  if (db->batch != NULL || level != 1)
    return LSM_MISUSE;

  db->batch = leveldb_writebatch_create();

  return LSM_OK;
}

int
lsm_insert(lsm_db *db, const void *kp, int kn, const void *vp, int vn) {
  if (db->batch == NULL)
    return LSM_MISUSE;

  leveldb_writebatch_put(db->batch, kp, kn, vp, vn);

  return LSM_OK;
}

int
lsm_delete(lsm_db *db, const void *kp, int kn) {
  if (db->batch == NULL)
    return LSM_MISUSE;

  leveldb_writebatch_delete(db->batch, kp, kn);

  return LSM_OK;
}

int
lsm_delete_range(lsm_db *db, const void *xp, int xn,
                             const void *yp, int yn) {
  leveldb_iterator_t *it;
  const void *kp;
  size_t kn;

  if (db->batch == NULL)
    return LSM_MISUSE;

  it = leveldb_create_iterator(db->level, db->iter_options);

  leveldb_iter_seek(it, xp, xn);

  while (leveldb_iter_valid(it)) {
    if (iter_compare(it, yp, yn) >= 0)
      break;

    kp = leveldb_iter_key(it, &kn);

    leveldb_writebatch_delete(db->batch, kp, kn);
  }

  leveldb_iter_destroy(it);

  return LSM_OK;
}

int
lsm_commit(lsm_db *db, int level) {
  char *err = NULL;

  if (db->batch == NULL || level != 0)
    return LSM_MISUSE;

  leveldb_write(db->level, db->write_options, db->batch, &err);
  leveldb_writebatch_destroy(db->batch);

  db->batch = NULL;

  if (err != NULL) {
    fprintf(stderr, "leveldb_write: %s\n", err);
    free(err);
    return LSM_ERROR;
  }

  return LSM_OK;
}

int
lsm_rollback(lsm_db *db, int level) {
  if (db->batch == NULL || level != 0)
    return LSM_MISUSE;

  leveldb_writebatch_destroy(db->batch);

  db->batch = NULL;

  return LSM_OK;
}

/*
 * Cursor
 */

int
lsm_csr_open(lsm_db *db, lsm_cursor **csr) {
  lsm_cursor *cur = (lsm_cursor *)malloc(sizeof(lsm_cursor));

  if (cur == NULL)
    return LSM_NOMEM;

  cur->it = leveldb_create_iterator(db->level, db->iter_options);
  cur->invalid = 0;

  *csr = cur;

  return LSM_OK;
}

int
lsm_csr_close(lsm_cursor *cur) {
  leveldb_iter_destroy(cur->it);
  free(cur);
  return LSM_OK;
}

int
lsm_csr_seek(lsm_cursor *cur, const void *kp, int kn, int whence) {
  cur->invalid = 0;

  leveldb_iter_seek(cur->it, kp, kn);

  if (whence == LSM_SEEK_EQ) {
    if (leveldb_iter_valid(cur->it) && iter_compare(cur->it, kp, kn) != 0)
      cur->invalid = 1;

    return LSM_OK;
  }

  if (whence == LSM_SEEK_LE) {
    while (leveldb_iter_valid(cur->it) && iter_compare(cur->it, kp, kn) > 0)
      leveldb_iter_prev(cur->it);

    return LSM_OK;
  }

  return LSM_OK;
}

int
lsm_csr_first(lsm_cursor *cur) {
  cur->invalid = 0;
  leveldb_iter_seek_to_first(cur->it);
  return LSM_OK;
}

int
lsm_csr_last(lsm_cursor *cur) {
  cur->invalid = 0;
  leveldb_iter_seek_to_last(cur->it);
  return LSM_OK;
}

int
lsm_csr_next(lsm_cursor *cur) {
  cur->invalid = 0;
  leveldb_iter_next(cur->it);
  return LSM_OK;
}

int
lsm_csr_prev(lsm_cursor *cur) {
  cur->invalid = 0;
  leveldb_iter_prev(cur->it);
  return LSM_OK;
}

int
lsm_csr_valid(lsm_cursor *cur) {
  return !cur->invalid && leveldb_iter_valid(cur->it);
}

int
lsm_csr_key(lsm_cursor *cur, const void **kp, int *kn) {
  size_t length;

  *kp = leveldb_iter_key(cur->it, &length);
  *kn = length;

  return LSM_OK;
}

int
lsm_csr_value(lsm_cursor *cur, const void **vp, int *vn) {
  size_t length;

  *vp = leveldb_iter_value(cur->it, &length);
  *vn = length;

  return LSM_OK;
}

int
lsm_csr_cmp(lsm_cursor *cur, const void *kp, int kn, int *cmp) {
  *cmp = iter_compare(cur->it, kp, kn);
  return LSM_OK;
}

/*
 * Util
 */

void *
lsm_malloc(lsm_env *env, size_t size) {
  CHECK(env == NULL);
  return malloc(size);
}

void *
lsm_realloc(lsm_env *env, void *ptr, size_t size) {
  CHECK(env == NULL);
  return realloc(ptr, size);
}

void
lsm_free(lsm_env *env, void *ptr) {
  CHECK(env == NULL);
  leveldb_free(ptr);
}
