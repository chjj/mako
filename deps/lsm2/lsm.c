/*!
 * lsm.c - leveldb wrapper for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdarg.h>
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
  leveldb_cache_t *cache;
  leveldb_filterpolicy_t *bloom;
  leveldb_readoptions_t *read_options;
  leveldb_writeoptions_t *write_options;
  leveldb_t *level;
  leveldb_writebatch_t *batch;
};

struct lsm_cursor {
  leveldb_iterator_t *it;
  int invalid;
};

/*
 * Error Handling
 */

static int
convert_error(char *err) {
  /* https://github.com/google/leveldb/blob/f57513a/include/leveldb/status.h */
  /* https://github.com/google/leveldb/blob/f57513a/util/status.cc#L38 */
  char *p;

  if (err == NULL)
    return LSM_OK;

  p = strchr(err, ':');

  if (p != NULL)
    *p = '\0';

  if (strcmp(err, "OK") == 0)
    return LSM_OK;

  if (strcmp(err, "NotFound") == 0)
    return LSM_CANTOPEN; /* LSM_IOERR_NOENT */

  if (strcmp(err, "Corruption") == 0)
    return LSM_CORRUPT;

  if (strcmp(err, "Not implemented") == 0)
    return LSM_PROTOCOL;

  if (strcmp(err, "Invalid argument") == 0)
    return LSM_MISUSE;

  if (strcmp(err, "IO error") == 0)
    return LSM_IOERR;

  return LSM_ERROR;
}

static int
handle_error(char *err) {
  int rc = convert_error(err);

  if (err != NULL)
    free(err);

  return rc;
}

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
  lsm_db *db;

  if (env != NULL)
    return LSM_MISUSE;

  db = malloc(sizeof(lsm_db));

  if (db == NULL)
    return LSM_NOMEM;

  options = leveldb_options_create();
  cache = leveldb_cache_create_lru(8 << 20);
  bloom = leveldb_filterpolicy_create_bloom(10);
  read_options = leveldb_readoptions_create();
  write_options = leveldb_writeoptions_create();

  leveldb_options_set_create_if_missing(options, 1);
  leveldb_options_set_error_if_exists(options, 0);
  leveldb_options_set_compression(options, leveldb_no_compression);
  leveldb_options_set_cache(options, cache);
  leveldb_options_set_write_buffer_size(options, 4 << 20);
  leveldb_options_set_block_size(options, 4096);
  leveldb_options_set_max_open_files(options, sizeof(void *) < 8 ? 64 : 1000);
  leveldb_options_set_block_restart_interval(options, 16);
  leveldb_options_set_max_file_size(options, 2 << 20);
  leveldb_options_set_filter_policy(options, bloom);
  leveldb_options_set_paranoid_checks(options, 0);

  leveldb_readoptions_set_verify_checksums(read_options, 0);
  leveldb_readoptions_set_fill_cache(read_options, 1);

  leveldb_writeoptions_set_sync(write_options, 0);

  db->options = options;
  db->cache = cache;
  db->bloom = bloom;
  db->read_options = read_options;
  db->write_options = write_options;
  db->level = NULL;
  db->batch = NULL;

  *lsm = db;

  return LSM_OK;
}

int
lsm_open(lsm_db *db, const char *file) {
  size_t len = strlen(file);
  char *err = NULL;
  char path[1024];

  if (len + 1 > sizeof(path))
    return LSM_MISUSE;

  memcpy(path, file, len + 1);

  if (len > 4 && strcmp(path + len - 4, ".dat") == 0)
    path[len - 4] = '\0';

  db->level = leveldb_open(db->options, path, &err);

  return handle_error(err);
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
  leveldb_cache_destroy(db->cache);
  leveldb_filterpolicy_destroy(db->bloom);
  leveldb_readoptions_destroy(db->read_options);
  leveldb_writeoptions_destroy(db->write_options);

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

  (void)merge;
  (void)kb;

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
    case LSM_CONFIG_AUTOFLUSH:
    case LSM_CONFIG_AUTOWORK:
    case LSM_CONFIG_AUTOCHECKPOINT:
    case LSM_CONFIG_PAGE_SIZE:
    case LSM_CONFIG_SAFETY:
    case LSM_CONFIG_MMAP:
    case LSM_CONFIG_USE_LOG:
    case LSM_CONFIG_AUTOMERGE:
    case LSM_CONFIG_MAX_FREELIST:
    case LSM_CONFIG_MULTIPLE_PROCESSES:
    case LSM_CONFIG_READONLY: {
      int *ptr = va_arg(ap, int *);

      if (*ptr < 0)
        *ptr = 0;

      break;
    }

    case LSM_CONFIG_CREATE_IF_MISSING: {
      int val = *va_arg(ap, int *);

      if (val >= 0 && db->level == NULL)
        leveldb_options_set_create_if_missing(db->options, val);

      break;
    }

    case LSM_CONFIG_ERROR_IF_EXISTS: {
      int val = *va_arg(ap, int *);

      if (val >= 0 && db->level == NULL)
        leveldb_options_set_error_if_exists(db->options, val);

      break;
    }

    case LSM_CONFIG_COMPRESSION: {
      int val = *va_arg(ap, int *);

      if (val >= 0 && db->level == NULL)
        leveldb_options_set_compression(db->options, (val != 0));

      break;
    }

    case LSM_CONFIG_CACHE_SIZE: {
      int val = *va_arg(ap, int *);

      if (val >= 0 && db->level == NULL) {
        leveldb_cache_destroy(db->cache);

        db->cache = leveldb_cache_create_lru(val * 1024);

        leveldb_options_set_cache(db->options, db->cache);
      }

      break;
    }

    case LSM_CONFIG_BLOOM_BITS: {
      int val = *va_arg(ap, int *);

      if (val >= 0 && db->level == NULL) {
        leveldb_filterpolicy_destroy(db->bloom);

        db->bloom = leveldb_filterpolicy_create_bloom(val);

        leveldb_options_set_filter_policy(db->options, db->bloom);
      }

      break;
    }

    case LSM_CONFIG_BUFFER_SIZE: {
      int val = *va_arg(ap, int *);

      if (val >= 0 && db->level == NULL)
        leveldb_options_set_write_buffer_size(db->options, val * 1024);

      break;
    }

    case LSM_CONFIG_BLOCK_SIZE: {
      int val = *va_arg(ap, int *);

      if (val >= 0 && db->level == NULL)
        leveldb_options_set_block_size(db->options, val * 1024);

      break;
    }

    case LSM_CONFIG_MAX_OPEN_FILES: {
      int val = *va_arg(ap, int *);

      if (val >= 0 && db->level == NULL)
        leveldb_options_set_max_open_files(db->options, val);

      break;
    }

    case LSM_CONFIG_RESTART_INTERVAL: {
      int val = *va_arg(ap, int *);

      if (val >= 0 && db->level == NULL)
        leveldb_options_set_block_restart_interval(db->options, val);

      break;
    }

    case LSM_CONFIG_MAX_FILE_SIZE: {
      int val = *va_arg(ap, int *);

      if (val >= 0 && db->level == NULL)
        leveldb_options_set_max_file_size(db->options, val * 1024);

      break;
    }

    case LSM_CONFIG_PARANOID_CHECKS: {
      int val = *va_arg(ap, int *);

      if (val >= 0 && db->level == NULL)
        leveldb_options_set_paranoid_checks(db->options, val);

      break;
    }

    case LSM_CONFIG_VERIFY_CHECKSUMS: {
      int val = *va_arg(ap, int *);

      if (val >= 0)
        leveldb_readoptions_set_verify_checksums(db->read_options, val);

      break;
    }

    case LSM_CONFIG_FILL_CACHE: {
      int val = *va_arg(ap, int *);

      if (val >= 0)
        leveldb_readoptions_set_fill_cache(db->read_options, val);

      break;
    }

    case LSM_CONFIG_SYNC: {
      int val = *va_arg(ap, int *);

      if (val >= 0)
        leveldb_writeoptions_set_sync(db->write_options, val);

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
  unsigned char *vp;
  char *err = NULL;
  char key = 0;
  size_t vn;

  vp = (unsigned char *)leveldb_get(db->level,
                                    db->read_options,
                                    &key,
                                    sizeof(key),
                                    &vn,
                                    &err);

  if (err != NULL)
    return handle_error(err);

  if (vp != NULL) {
    if (vn != 4) {
      leveldb_free(vp);
      return LSM_CORRUPT;
    }

    *ptr = ((unsigned int)vp[0] << 24)
         | ((unsigned int)vp[1] << 16)
         | ((unsigned int)vp[2] <<  8)
         | ((unsigned int)vp[3] <<  0);

    leveldb_free(vp);
  } else {
    *ptr = 0;
  }

  return LSM_OK;
}

int
lsm_set_user_version(lsm_db *db, unsigned int val) {
  unsigned char vp[4];
  char *err = NULL;
  char key = 0;

  vp[0] = (val >> 24) & 0xff;
  vp[1] = (val >> 16) & 0xff;
  vp[2] = (val >>  8) & 0xff;
  vp[3] = (val >>  0) & 0xff;

  leveldb_put(db->level,
              db->write_options,
              &key,
              sizeof(key),
              (const char *)vp,
              sizeof(vp),
              &err);

  return handle_error(err);
}

int
lsm_info(lsm_db *db, int param, ...) {
  va_list ap;
  va_start(ap, param);
  va_end(ap);
  return LSM_MISUSE;
}

/*
 * Iterator Helpers
 */

static int
compare4(const void *xp, int xn, const void *yp, int yn) {
  int min = xn < yn ? xn : yn;
  int cmp = 0;

  if (min != 0)
    cmp = memcmp(xp, yp, min);

  if (cmp == 0)
    cmp = xn - yn;

  return cmp;
}

static int
iter_compare(leveldb_iterator_t *it, const void *yp, int yn) {
  const void *xp;
  size_t xn;

  xp = leveldb_iter_key(it, &xn);

  return compare4(xp, xn, yp, yn);
}

static int
iter_status(leveldb_iterator_t *it) {
  char *err = NULL;

  leveldb_iter_get_error(it, &err);

  return handle_error(err);
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
  int rc;

  if (db->batch == NULL)
    return LSM_MISUSE;

  it = leveldb_create_iterator(db->level, db->read_options);

  leveldb_iter_seek(it, xp, xn);

  if (leveldb_iter_valid(it) && iter_compare(it, xp, xn) == 0)
    leveldb_iter_next(it);

  while (leveldb_iter_valid(it)) {
    if (iter_compare(it, yp, yn) >= 0)
      break;

    kp = leveldb_iter_key(it, &kn);

    leveldb_writebatch_delete(db->batch, kp, kn);

    leveldb_iter_next(it);
  }

  rc = iter_status(it);

  leveldb_iter_destroy(it);

  return rc;
}

int
lsm_commit(lsm_db *db, int level) {
  char *err = NULL;

  if (db->batch == NULL || level != 0)
    return LSM_MISUSE;

  leveldb_write(db->level, db->write_options, db->batch, &err);
  leveldb_writebatch_destroy(db->batch);

  db->batch = NULL;

  return handle_error(err);
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
  lsm_cursor *cur = malloc(sizeof(lsm_cursor));

  if (cur == NULL)
    return LSM_NOMEM;

  cur->it = leveldb_create_iterator(db->level, db->read_options);
  cur->invalid = 0;

  *csr = cur;

  return LSM_OK;
}

int
lsm_csr_close(lsm_cursor *cur) {
  int rc = iter_status(cur->it);
  leveldb_iter_destroy(cur->it);
  free(cur);
  return rc;
}

int
lsm_csr_seek(lsm_cursor *cur, const void *kp, int kn, int whence) {
  cur->invalid = 0;

  switch (whence) {
    case LSM_SEEK_LE: {
      leveldb_iter_seek(cur->it, kp, kn);

      if (leveldb_iter_valid(cur->it) && iter_compare(cur->it, kp, kn) > 0)
        leveldb_iter_prev(cur->it);

      return LSM_OK;
    }

    case LSM_SEEK_EQ: {
      leveldb_iter_seek(cur->it, kp, kn);

      if (leveldb_iter_valid(cur->it) && iter_compare(cur->it, kp, kn) != 0)
        cur->invalid = 1;

      return LSM_OK;
    }

    case LSM_SEEK_GE: {
      leveldb_iter_seek(cur->it, kp, kn);
      return LSM_OK;
    }
  }

  return LSM_MISUSE;
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

  if (ptr != NULL)
    free(ptr);
}
