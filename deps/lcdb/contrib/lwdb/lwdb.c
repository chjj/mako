/*!
 * lwdb.c - wrap leveldb to look like lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on google/leveldb:
 *   Copyright (c) 2011, The LevelDB Authors. All rights reserved.
 *   https://github.com/google/leveldb
 *
 * See LICENSE for more information.
 */

#include <assert.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <leveldb/c.h>

/*
 * Options
 */

/* Define to assume latest leveldb version. */
/* #undef LWDB_LATEST */

/*
 * Macros
 */

#ifdef LDB_EXPORT
#  if defined(_WIN32)
#    define LDB_EXTERN __declspec(dllexport)
#  elif defined(__GNUC__) && __GNUC__ >= 4
#    define LDB_EXTERN __attribute__((visibility("default")))
#  endif
#endif

#ifndef LDB_EXTERN
#  define LDB_EXTERN
#endif

#define lengthof(x) (sizeof(x) / sizeof((x)[0]))

/*
 * Constants
 */

#define LDB_OK (0)
#define LDB_NOTFOUND (-1)
#define LDB_CORRUPTION (-2)
#define LDB_NOSUPPORT (-3)
#define LDB_INVALID (-4)
#define LDB_IOERR (-5)

enum ldb_compression {
  LDB_NO_COMPRESSION = 0,
  LDB_SNAPPY_COMPRESSION = 1
};

/*
 * Types
 */

typedef struct ldb_s ldb_t;
typedef struct ldb_batch_s ldb_batch_t;
typedef struct ldb_bloom_s ldb_bloom_t;
typedef struct ldb_comparator_s ldb_comparator_t;
typedef struct ldb_dbopt_s ldb_dbopt_t;
typedef struct ldb_handler_s ldb_handler_t;
typedef struct ldb_iter_s ldb_iter_t;
typedef struct ldb_logger_s ldb_logger_t;
typedef leveldb_cache_t ldb_lru_t;
typedef struct ldb_range_s ldb_range_t;
typedef struct ldb_readopt_s ldb_readopt_t;
typedef struct ldb_slice_s ldb_slice_t;
typedef leveldb_snapshot_t ldb_snapshot_t;
typedef struct ldb_writeopt_s ldb_writeopt_t;

struct ldb_slice_s {
  void *data;
  size_t size;
  size_t dummy;
};

struct ldb_batch_s {
  leveldb_writebatch_t *rep;
  size_t dummy1;
  size_t dummy2;
};

struct ldb_bloom_s {
  leveldb_filterpolicy_t *rep;
};

struct ldb_comparator_s {
  const char *name;
  int (*compare)(const ldb_comparator_t *,
                 const ldb_slice_t *,
                 const ldb_slice_t *);
  void (*dummy1)(void);
  void (*dummy2)(void);
  void *dummy3;
  void *dummy4;
};

struct ldb_dbopt_s {
  ldb_comparator_t *comparator;
  int create_if_missing;
  int error_if_exists;
  int paranoid_checks;
  ldb_logger_t *info_log;
  size_t write_buffer_size;
  int max_open_files;
  ldb_lru_t *block_cache;
  size_t block_size;
  int block_restart_interval;
  size_t max_file_size;
  enum ldb_compression compression;
  int reuse_logs;
  ldb_bloom_t *filter_policy;
  int use_mmap;
};

struct ldb_handler_s {
  void *state;
  uint64_t number;

  void (*put)(ldb_handler_t *handler,
              const ldb_slice_t *key,
              const ldb_slice_t *value);

  void (*del)(ldb_handler_t *handler,
              const ldb_slice_t *key);
};

struct ldb_iter_s {
  leveldb_iterator_t *rep;
  leveldb_readoptions_t *options;
  const ldb_comparator_t *ucmp;
};

struct ldb_logger_s {
  leveldb_logger_t *rep;
};

struct ldb_range_s {
  ldb_slice_t start;
  ldb_slice_t limit;
};

struct ldb_readopt_s {
  int verify_checksums;
  int fill_cache;
  const ldb_snapshot_t *snapshot;
};

struct ldb_writeopt_s {
  int sync;
};

struct ldb_s {
  ldb_comparator_t ucmp;
  ldb_dbopt_t dbopt;
  leveldb_comparator_t *cmp;
  leveldb_filterpolicy_t *policy;
  leveldb_options_t *options;
  leveldb_readoptions_t *read_options;
  leveldb_writeoptions_t *write_options;
  leveldb_readoptions_t *iter_options;
  leveldb_t *level;
};

/*
 * Globals
 */

LDB_EXTERN extern const ldb_bloom_t *ldb_bloom_default;
LDB_EXTERN extern const ldb_comparator_t *ldb_bytewise_comparator;
LDB_EXTERN extern const ldb_dbopt_t *ldb_dbopt_default;
LDB_EXTERN extern const ldb_readopt_t *ldb_readopt_default;
LDB_EXTERN extern const ldb_writeopt_t *ldb_writeopt_default;
LDB_EXTERN extern const ldb_readopt_t *ldb_iteropt_default;

/*
 * Functions
 */

/* Batch */
LDB_EXTERN ldb_batch_t *
ldb_batch_create(void);

LDB_EXTERN void
ldb_batch_destroy(ldb_batch_t *batch);

LDB_EXTERN void
ldb_batch_init(ldb_batch_t *batch);

LDB_EXTERN void
ldb_batch_clear(ldb_batch_t *batch);

LDB_EXTERN void
ldb_batch_reset(ldb_batch_t *batch);

LDB_EXTERN void
ldb_batch_put(ldb_batch_t *batch,
              const ldb_slice_t *key,
              const ldb_slice_t *value);

LDB_EXTERN void
ldb_batch_del(ldb_batch_t *batch, const ldb_slice_t *key);

LDB_EXTERN int
ldb_batch_iterate(const ldb_batch_t *batch, ldb_handler_t *handler);

LDB_EXTERN void
ldb_batch_append(ldb_batch_t *dst, const ldb_batch_t *src);

/* Bloom */
LDB_EXTERN ldb_bloom_t *
ldb_bloom_create(int bits_per_key);

LDB_EXTERN void
ldb_bloom_destroy(ldb_bloom_t *bloom);

/* Cache */
LDB_EXTERN ldb_lru_t *
ldb_lru_create(size_t capacity);

LDB_EXTERN void
ldb_lru_destroy(ldb_lru_t *lru);

/* Database */
LDB_EXTERN int
ldb_open(const char *dbname, const ldb_dbopt_t *options, ldb_t **dbptr);

LDB_EXTERN void
ldb_close(ldb_t *db);

LDB_EXTERN int
ldb_get(ldb_t *db, const ldb_slice_t *key,
                   ldb_slice_t *value,
                   const ldb_readopt_t *options);

LDB_EXTERN int
ldb_has(ldb_t *db, const ldb_slice_t *key, const ldb_readopt_t *options);

LDB_EXTERN int
ldb_put(ldb_t *db, const ldb_slice_t *key,
                   const ldb_slice_t *value,
                   const ldb_writeopt_t *options);

LDB_EXTERN int
ldb_del(ldb_t *db, const ldb_slice_t *key, const ldb_writeopt_t *options);

LDB_EXTERN int
ldb_write(ldb_t *db, ldb_batch_t *updates, const ldb_writeopt_t *options);

LDB_EXTERN const ldb_snapshot_t *
ldb_snapshot(ldb_t *db);

LDB_EXTERN void
ldb_release(ldb_t *db, const ldb_snapshot_t *snapshot);

LDB_EXTERN int
ldb_property(ldb_t *db, const char *property, char **value);

LDB_EXTERN void
ldb_approximate_sizes(ldb_t *db, const ldb_range_t *range,
                                 size_t length,
                                 uint64_t *sizes);

LDB_EXTERN void
ldb_compact(ldb_t *db, const ldb_slice_t *begin, const ldb_slice_t *end);

LDB_EXTERN int
ldb_backup(ldb_t *db, const char *name);

LDB_EXTERN int
ldb_compare(const ldb_t *db, const ldb_slice_t *x, const ldb_slice_t *y);

/* Static */
LDB_EXTERN int
ldb_repair(const char *dbname, const ldb_dbopt_t *options);

LDB_EXTERN int
ldb_copy(const char *from, const char *to, const ldb_dbopt_t *options);

LDB_EXTERN int
ldb_destroy(const char *dbname, const ldb_dbopt_t *options);

/* Filesystem */
LDB_EXTERN int
ldb_test_directory(char *result, size_t size);

LDB_EXTERN int
ldb_test_filename(char *result, size_t size, const char *name);

/* Internal */
LDB_EXTERN void
ldb_assert_fail(const char *file, int line, const char *expr);

LDB_EXTERN void
ldb_free(void *ptr);

/* Iterator */
LDB_EXTERN ldb_iter_t *
ldb_iterator(ldb_t *db, const ldb_readopt_t *options);

LDB_EXTERN void
ldb_iter_destroy(ldb_iter_t *iter);

LDB_EXTERN int
ldb_iter_valid(const ldb_iter_t *iter);

LDB_EXTERN void
ldb_iter_first(ldb_iter_t *iter);

LDB_EXTERN void
ldb_iter_last(ldb_iter_t *iter);

LDB_EXTERN void
ldb_iter_seek(ldb_iter_t *iter, const ldb_slice_t *target);

LDB_EXTERN void
ldb_iter_next(ldb_iter_t *iter);

LDB_EXTERN void
ldb_iter_prev(ldb_iter_t *iter);

LDB_EXTERN ldb_slice_t
ldb_iter_key(const ldb_iter_t *iter);

LDB_EXTERN ldb_slice_t
ldb_iter_value(const ldb_iter_t *iter);

LDB_EXTERN int
ldb_iter_status(const ldb_iter_t *iter);

LDB_EXTERN int
ldb_iter_compare(const ldb_iter_t *iter, const ldb_slice_t *key);

LDB_EXTERN void
ldb_iter_seek_ge(ldb_iter_t *iter, const ldb_slice_t *target);

LDB_EXTERN void
ldb_iter_seek_gt(ldb_iter_t *iter, const ldb_slice_t *target);

LDB_EXTERN void
ldb_iter_seek_le(ldb_iter_t *iter, const ldb_slice_t *target);

LDB_EXTERN void
ldb_iter_seek_lt(ldb_iter_t *iter, const ldb_slice_t *target);

/* Logging */
LDB_EXTERN ldb_logger_t *
ldb_logger_create(void (*logv)(void *, const char *, va_list), void *state);

LDB_EXTERN void
ldb_logger_destroy(ldb_logger_t *logger);

/* Slice */
LDB_EXTERN ldb_slice_t
ldb_slice(const void *xp, size_t xn);

LDB_EXTERN ldb_slice_t
ldb_string(const char *xp);

/* Status */
LDB_EXTERN const char *
ldb_strerror(int code);

/*
 * Helpers
 */

static void *
safe_malloc(size_t size) {
  void *ptr = malloc(size);

  if (ptr == NULL)
    abort(); /* LCOV_EXCL_LINE */

  return ptr;
}

static void
safe_free(void *ptr) {
  if (ptr != NULL)
    free(ptr);
}

static int
convert_error(char *err) {
  /* https://github.com/google/leveldb/blob/f57513a/include/leveldb/status.h */
  /* https://github.com/google/leveldb/blob/f57513a/util/status.cc#L38 */
  char *p;

  if (err == NULL)
    return LDB_OK;

  p = strchr(err, ':');

  if (p != NULL)
    *p = '\0';

  assert(strcmp(err, "OK") != 0);

  if (strcmp(err, "NotFound") == 0)
    return LDB_NOTFOUND;

  if (strcmp(err, "Corruption") == 0)
    return LDB_CORRUPTION;

  if (strcmp(err, "Not implemented") == 0)
    return LDB_NOSUPPORT;

  if (strcmp(err, "Invalid argument") == 0)
    return LDB_INVALID;

  if (strcmp(err, "IO error") == 0)
    return LDB_IOERR;

  return LDB_INVALID;
}

static int
handle_error(char *err) {
  int rc = convert_error(err);

  if (err != NULL)
    safe_free(err);

  return rc;
}

static int
slice_compare(const ldb_comparator_t *comparator,
              const ldb_slice_t *x,
              const ldb_slice_t *y) {
  size_t n = x->size < y->size ? x->size : y->size;
  int r = n ? memcmp(x->data, y->data, n) : 0;

  (void)comparator;

  if (r == 0) {
    if (x->size < y->size)
      r = -1;
    else if (x->size > y->size)
      r = +1;
  }

  return r;
}

static void
comparator_destructor(void *state) {
  (void)state;
}

static int
comparator_compare(void *state, const char *a, size_t alen,
                                const char *b, size_t blen) {
  const ldb_comparator_t *cmp = state;
  ldb_slice_t x, y;

  x.data = (void *)a;
  x.size = alen;

  y.data = (void *)b;
  y.size = blen;

  return cmp->compare(cmp, &x, &y);
}

static const char *
comparator_name(void *state) {
  const ldb_comparator_t *cmp = state;
  return cmp->name;
}

static leveldb_comparator_t *
convert_comparator(ldb_comparator_t *cmp) {
  if (cmp == NULL)
    return NULL;

  if (cmp->name == ldb_bytewise_comparator->name &&
      cmp->compare == ldb_bytewise_comparator->compare) {
    return NULL;
  }

  return leveldb_comparator_create(cmp, comparator_destructor,
                                        comparator_compare,
                                        comparator_name);
}

static leveldb_options_t *
convert_dbopt(const ldb_dbopt_t *x,
              leveldb_comparator_t *cmp,
              leveldb_filterpolicy_t **policy) {
  leveldb_options_t *z = leveldb_options_create();

  if (cmp != NULL)
    leveldb_options_set_comparator(z, cmp);

  leveldb_options_set_create_if_missing(z, x->create_if_missing);
  leveldb_options_set_error_if_exists(z, x->error_if_exists);
  leveldb_options_set_paranoid_checks(z, x->paranoid_checks);

  if (x->info_log != NULL)
    leveldb_options_set_info_log(z, x->info_log->rep);

  leveldb_options_set_write_buffer_size(z, x->write_buffer_size);
  leveldb_options_set_max_open_files(z, x->max_open_files);

  if (x->block_cache != NULL)
    leveldb_options_set_cache(z, x->block_cache);

  leveldb_options_set_block_size(z, x->block_size);
  leveldb_options_set_block_restart_interval(z, x->block_restart_interval);
#ifdef LWDB_LATEST
  /* Requires leveldb 1.21 (March 2019). */
  leveldb_options_set_max_file_size(z, x->max_file_size);
#endif
  leveldb_options_set_compression(z, x->compression);

  /* Maybe someday... */
  /* leveldb_options_set_reuse_logs(z, x->reuse_logs); */

  if (x->filter_policy != NULL) {
    if (x->filter_policy->rep == NULL) {
      *policy = leveldb_filterpolicy_create_bloom(10);
      leveldb_options_set_filter_policy(z, *policy);
    } else {
      leveldb_options_set_filter_policy(z, x->filter_policy->rep);
    }
  }

  return z;
}

static leveldb_readoptions_t *
convert_readopt(const ldb_readopt_t *x) {
  leveldb_readoptions_t *z = leveldb_readoptions_create();

  leveldb_readoptions_set_verify_checksums(z, x->verify_checksums);
  leveldb_readoptions_set_fill_cache(z, x->fill_cache);
  leveldb_readoptions_set_snapshot(z, x->snapshot);

  return z;
}

static leveldb_writeoptions_t *
convert_writeopt(const ldb_writeopt_t *x) {
  leveldb_writeoptions_t *z = leveldb_writeoptions_create();

  leveldb_writeoptions_set_sync(z, x->sync);

  return z;
}

/*
 * Batch
 */

ldb_batch_t *
ldb_batch_create(void) {
  ldb_batch_t *batch = safe_malloc(sizeof(ldb_batch_t));
  batch->rep = leveldb_writebatch_create();
  return batch;
}

void
ldb_batch_destroy(ldb_batch_t *batch) {
  leveldb_writebatch_destroy(batch->rep);
  safe_free(batch);
}

void
ldb_batch_init(ldb_batch_t *batch) {
  batch->rep = leveldb_writebatch_create();
}

void
ldb_batch_clear(ldb_batch_t *batch) {
  leveldb_writebatch_destroy(batch->rep);
}

void
ldb_batch_reset(ldb_batch_t *batch) {
  leveldb_writebatch_destroy(batch->rep);

  batch->rep = leveldb_writebatch_create();
}

void
ldb_batch_put(ldb_batch_t *batch,
              const ldb_slice_t *key,
              const ldb_slice_t *value) {
  leveldb_writebatch_put(batch->rep, key->data, key->size,
                                     value->data, value->size);
}

void
ldb_batch_del(ldb_batch_t *batch, const ldb_slice_t *key) {
  leveldb_writebatch_delete(batch->rep, key->data, key->size);
}

static void
batch_put(void *state, const char *k, size_t klen,
                       const char *v, size_t vlen) {
  ldb_handler_t *handler = state;
  ldb_slice_t key, val;

  key.data = (void *)k;
  key.size = klen;

  val.data = (void *)v;
  val.size = vlen;

  handler->put(handler, &key, &val);
}

static void
batch_del(void *state, const char *k, size_t klen) {
  ldb_handler_t *handler = state;
  ldb_slice_t key;

  key.data = (void *)k;
  key.size = klen;

  handler->del(handler, &key);
}

int
ldb_batch_iterate(const ldb_batch_t *batch, ldb_handler_t *handler) {
  leveldb_writebatch_iterate(batch->rep, handler, batch_put, batch_del);
  return LDB_OK;
}

#ifndef LWDB_LATEST
static void
append_put(void *state, const char *k, size_t klen,
                        const char *v, size_t vlen) {
  leveldb_writebatch_put(state, k, klen, v, vlen);
}

static void
append_del(void *state, const char *k, size_t klen) {
  leveldb_writebatch_delete(state, k, klen);
}
#endif

void
ldb_batch_append(ldb_batch_t *dst, const ldb_batch_t *src) {
#ifdef LWDB_LATEST
  /* Requires leveldb 1.21 (March 2019). */
  leveldb_writebatch_append(dst->rep, src->rep);
#else
  leveldb_writebatch_iterate(src->rep, dst->rep,
                             append_put, append_del);
#endif
}

/*
 * Bloom
 */

static const ldb_bloom_t bloom_default = {NULL};

const ldb_bloom_t *ldb_bloom_default = &bloom_default;

ldb_bloom_t *
ldb_bloom_create(int bits_per_key) {
  ldb_bloom_t *bloom = safe_malloc(sizeof(ldb_bloom_t));
  /* Requires leveldb 1.4 (April 2012). */
  bloom->rep = leveldb_filterpolicy_create_bloom(bits_per_key);
  return bloom;
}

void
ldb_bloom_destroy(ldb_bloom_t *bloom) {
  leveldb_filterpolicy_destroy(bloom->rep);
  safe_free(bloom);
}

/*
 * Cache
 */

ldb_lru_t *
ldb_lru_create(size_t capacity) {
  return leveldb_cache_create_lru(capacity);
}

void
ldb_lru_destroy(ldb_lru_t *lru) {
  leveldb_cache_destroy(lru);
}

/*
 * Comparator
 */

static const ldb_comparator_t bytewise_comparator = {
  /* .name = */ "leveldb.BytewiseComparator",
  /* .compare = */ slice_compare,
  /* .shortest_separator = */ NULL,
  /* .short_successor = */ NULL,
  /* .user_comparator = */ NULL,
  /* .state = */ NULL
};

const ldb_comparator_t *ldb_bytewise_comparator = &bytewise_comparator;

/*
 * Database
 */

int
ldb_open(const char *dbname, const ldb_dbopt_t *options, ldb_t **dbptr) {
  char *err = NULL;
  ldb_t *db;
  int rc;

  *dbptr = NULL;

  if (options == NULL)
    return LDB_INVALID;

  db = safe_malloc(sizeof(ldb_t));

  if (options->comparator != NULL)
    db->ucmp = *options->comparator;
  else
    db->ucmp = bytewise_comparator;

  db->dbopt = *options;
  db->dbopt.comparator = &db->ucmp;
  db->cmp = convert_comparator(&db->ucmp);
  db->policy = NULL;
  db->options = convert_dbopt(options, db->cmp, &db->policy);
  db->read_options = convert_readopt(ldb_readopt_default);
  db->write_options = convert_writeopt(ldb_writeopt_default);
  db->iter_options = convert_readopt(ldb_iteropt_default);
  db->level = leveldb_open(db->options, dbname, &err);

  rc = handle_error(err);

  if (rc == LDB_OK)
    *dbptr = db;
  else
    ldb_close(db);

  return rc;
}

void
ldb_close(ldb_t *db) {
  if (db->level != NULL)
    leveldb_close(db->level);

  if (db->cmp != NULL)
    leveldb_comparator_destroy(db->cmp);

  if (db->policy != NULL)
    leveldb_filterpolicy_destroy(db->policy);

  leveldb_options_destroy(db->options);
  leveldb_readoptions_destroy(db->read_options);
  leveldb_writeoptions_destroy(db->write_options);
  leveldb_readoptions_destroy(db->iter_options);

  safe_free(db);
}

int
ldb_get(ldb_t *db, const ldb_slice_t *key,
                   ldb_slice_t *value,
                   const ldb_readopt_t *options) {
  leveldb_readoptions_t *opt = db->read_options;
  char *err = NULL;
  int rc;

  if (options != NULL)
    opt = convert_readopt(options);

  value->data = leveldb_get(db->level,
                            opt,
                            key->data,
                            key->size,
                            &value->size,
                            &err);
  value->dummy = 0;

  rc = handle_error(err);

  if (rc == LDB_OK && value->data == NULL)
    rc = LDB_NOTFOUND;

  if (options != NULL)
    leveldb_readoptions_destroy(opt);

  return rc;
}

int
ldb_has(ldb_t *db, const ldb_slice_t *key, const ldb_readopt_t *options) {
  ldb_slice_t val;
  int rc;

  rc = ldb_get(db, key, &val, options);

  if (rc == LDB_OK)
    leveldb_free(val.data);

  return rc;
}

int
ldb_put(ldb_t *db, const ldb_slice_t *key,
                   const ldb_slice_t *value,
                   const ldb_writeopt_t *options) {
  leveldb_writeoptions_t *opt = db->write_options;
  char *err = NULL;

  if (options != NULL)
    opt = convert_writeopt(options);

  leveldb_put(db->level,
              opt,
              key->data,
              key->size,
              value->data,
              value->size,
              &err);

  if (options != NULL)
    leveldb_writeoptions_destroy(opt);

  return handle_error(err);
}

int
ldb_del(ldb_t *db, const ldb_slice_t *key, const ldb_writeopt_t *options) {
  leveldb_writeoptions_t *opt = db->write_options;
  char *err = NULL;

  if (options != NULL)
    opt = convert_writeopt(options);

  leveldb_delete(db->level, opt, key->data, key->size, &err);

  if (options != NULL)
    leveldb_writeoptions_destroy(opt);

  return handle_error(err);
}

int
ldb_write(ldb_t *db, ldb_batch_t *updates, const ldb_writeopt_t *options) {
  leveldb_writeoptions_t *opt = db->write_options;
  char *err = NULL;

  if (updates == NULL)
    return LDB_INVALID;

  if (options != NULL)
    opt = convert_writeopt(options);

  leveldb_write(db->level, opt, updates->rep, &err);

  if (options != NULL)
    leveldb_writeoptions_destroy(opt);

  return handle_error(err);
}

const ldb_snapshot_t *
ldb_snapshot(ldb_t *db) {
  return leveldb_create_snapshot(db->level);
}

void
ldb_release(ldb_t *db, const ldb_snapshot_t *snapshot) {
  leveldb_release_snapshot(db->level, snapshot);
}

int
ldb_property(ldb_t *db, const char *property, char **value) {
  *value = leveldb_property_value(db->level, property);
  return *value != NULL;
}

void
ldb_approximate_sizes(ldb_t *db, const ldb_range_t *range,
                                 size_t length,
                                 uint64_t *sizes) {
  const char **start_keys = safe_malloc(length * sizeof(char *));
  const char **limit_keys = safe_malloc(length * sizeof(char *));
  size_t *start_lens = safe_malloc(length * sizeof(size_t));
  size_t *limit_lens = safe_malloc(length * sizeof(size_t));
  size_t i;

  for (i = 0; i < length; i++) {
    start_keys[i] = range[i].start.data;
    start_lens[i] = range[i].start.size;
    limit_keys[i] = range[i].limit.data;
    limit_lens[i] = range[i].limit.size;
  }

  leveldb_approximate_sizes(db->level, length,
                            start_keys, start_lens,
                            limit_keys, limit_lens,
                            sizes);

  safe_free(start_keys);
  safe_free(start_lens);
  safe_free(limit_keys);
  safe_free(limit_lens);
}

void
ldb_compact(ldb_t *db, const ldb_slice_t *begin, const ldb_slice_t *end) {
  static const ldb_slice_t empty = {NULL, 0, 0};

  if (begin == NULL)
    begin = &empty;

  if (end == NULL)
    end = &empty;

  leveldb_compact_range(db->level, begin->data, begin->size,
                                   end->data, end->size);
}

int
ldb_backup(ldb_t *db, const char *name) {
  ldb_readopt_t iopt = *ldb_iteropt_default;
  ldb_dbopt_t opt = db->dbopt;
  ldb_batch_t batch;
  size_t size = 0;
  ldb_iter_t *it;
  ldb_t *bak;
  int rc;

  opt.create_if_missing = 1;
  opt.error_if_exists = 1;
  opt.info_log = NULL;
  opt.block_cache = NULL;

  if (opt.write_buffer_size < (64 << 10))
    opt.write_buffer_size = 64 << 10;

  rc = ldb_open(name, &opt, &bak);

  if (rc != LDB_OK)
    return rc;

  iopt.snapshot = ldb_snapshot(db);

  it = ldb_iterator(db, &iopt);

  ldb_batch_init(&batch);

  for (ldb_iter_first(it); ldb_iter_valid(it); ldb_iter_next(it)) {
    ldb_slice_t key = ldb_iter_key(it);
    ldb_slice_t val = ldb_iter_value(it);

    if (size >= opt.write_buffer_size) {
      rc = ldb_write(bak, &batch, NULL);

      if (rc != LDB_OK)
        break;

      ldb_batch_reset(&batch);

      size = 0;
    }

    size += 6;
    size += key.size;
    size += val.size;

    ldb_batch_put(&batch, &key, &val);
  }

  if (rc == LDB_OK)
    rc = ldb_iter_status(it);

  ldb_iter_destroy(it);
  ldb_release(db, iopt.snapshot);

  if (rc == LDB_OK && size > 0)
    rc = ldb_write(bak, &batch, NULL);

  ldb_batch_clear(&batch);

  if (rc == LDB_OK && size > 0)
    ldb_compact(bak, NULL, NULL);

  ldb_close(bak);

  if (rc != LDB_OK)
    ldb_destroy(name, &opt);

  return rc;
}

int
ldb_compare(const ldb_t *db, const ldb_slice_t *x, const ldb_slice_t *y) {
  return db->ucmp.compare(&db->ucmp, x, y);
}

/*
 * Static
 */

int
ldb_repair(const char *dbname, const ldb_dbopt_t *options) {
  leveldb_filterpolicy_t *policy = NULL;
  leveldb_comparator_t *cmp;
  leveldb_options_t *opt;
  char *err = NULL;

  if (options == NULL)
    return LDB_INVALID;

  cmp = convert_comparator(options->comparator);
  opt = convert_dbopt(options, cmp, &policy);

  leveldb_repair_db(opt, dbname, &err);

  if (cmp != NULL)
    leveldb_comparator_destroy(cmp);

  if (policy != NULL)
    leveldb_filterpolicy_destroy(policy);

  leveldb_options_destroy(opt);

  return handle_error(err);
}

int
ldb_copy(const char *from, const char *to, const ldb_dbopt_t *options) {
  ldb_dbopt_t opt;
  ldb_t *db;
  int rc;

  if (options == NULL)
    return LDB_INVALID;

  opt = *options;
  opt.create_if_missing = 0;
  opt.error_if_exists = 0;

  rc = ldb_open(from, &opt, &db);

  if (rc != LDB_OK)
    return rc;

  rc = ldb_backup(db, to);

  ldb_close(db);

  return rc;
}

int
ldb_destroy(const char *dbname, const ldb_dbopt_t *options) {
  leveldb_filterpolicy_t *policy = NULL;
  leveldb_comparator_t *cmp;
  leveldb_options_t *opt;
  char *err = NULL;

  if (options == NULL)
    options = ldb_dbopt_default;

  cmp = convert_comparator(options->comparator);
  opt = convert_dbopt(options, cmp, &policy);

  leveldb_destroy_db(opt, dbname, &err);

  if (cmp != NULL)
    leveldb_comparator_destroy(cmp);

  if (policy != NULL)
    leveldb_filterpolicy_destroy(policy);

  leveldb_options_destroy(opt);

  return handle_error(err);
}

/*
 * Filesystem
 */

#ifndef LWDB_LATEST
#  ifdef _WIN32
#    include <windows.h>
#  else
#    include <sys/types.h>
#    include <sys/stat.h>
#  endif
#endif

int
ldb_test_directory(char *result, size_t size) {
#ifdef LWDB_LATEST
  leveldb_env_t *env = leveldb_create_default_env();
  /* Requires leveldb 1.21 (March 2019). */
  char *path = leveldb_env_get_test_directory(env);
  size_t len;

  leveldb_env_destroy(env);

  if (path == NULL)
    return 0;

  len = strlen(path);

  if (len + 1 > size) {
    safe_free(path);
    return 0;
  }

  memcpy(result, path, len + 1);

  safe_free(path);

  return 1;
#else /* !LWDB_LATEST */
#ifdef _WIN32
  static const char tmp[] = "C:/temp/leveldbtest";
#else
  static const char tmp[] = "/tmp/leveldbtest";
#endif

  if (sizeof(tmp) > size)
    return 0;

  memcpy(result, tmp, sizeof(tmp));

#ifdef _WIN32
  CreateDirectoryA("C:/temp", NULL);
  CreateDirectoryA(tmp, NULL);
#else
  mkdir(tmp, 0755);
#endif

  return 1;
#endif /* !LWDB_LATEST */
}

int
ldb_test_filename(char *result, size_t size, const char *name) {
  char path[1024];

  if (!ldb_test_directory(path, sizeof(path)))
    return 0;

  if (strlen(path) + strlen(name) + 2 > size)
    return 0;

  sprintf(result, "%s/%s", path, name);

  return 1;
}

/*
 * Internal
 */

void
ldb_assert_fail(const char *file, int line, const char *expr) {
  /* LCOV_EXCL_START */
  fprintf(stderr, "%s:%d: Assertion `%s' failed.\n", file, line, expr);
  fflush(stderr);
  abort();
  /* LCOV_EXCL_STOP */
}

void
ldb_free(void *ptr) {
  leveldb_free(ptr);
}

/*
 * Iterator
 */

ldb_iter_t *
ldb_iterator(ldb_t *db, const ldb_readopt_t *options) {
  ldb_iter_t *iter = safe_malloc(sizeof(ldb_iter_t));
  leveldb_readoptions_t *opt = db->iter_options;

  if (options != NULL) {
    opt = convert_readopt(options);
    iter->options = opt;
  } else {
    iter->options = NULL;
  }

  iter->rep = leveldb_create_iterator(db->level, opt);
  iter->ucmp = &db->ucmp;

  return iter;
}

void
ldb_iter_destroy(ldb_iter_t *iter) {
  leveldb_iter_destroy(iter->rep);

  if (iter->options != NULL)
    leveldb_readoptions_destroy(iter->options);

  safe_free(iter);
}

int
ldb_iter_valid(const ldb_iter_t *iter) {
  return leveldb_iter_valid(iter->rep);
}

void
ldb_iter_first(ldb_iter_t *iter) {
  leveldb_iter_seek_to_first(iter->rep);
}

void
ldb_iter_last(ldb_iter_t *iter) {
  leveldb_iter_seek_to_last(iter->rep);
}

void
ldb_iter_seek(ldb_iter_t *iter, const ldb_slice_t *target) {
  leveldb_iter_seek(iter->rep, target->data, target->size);
}

void
ldb_iter_next(ldb_iter_t *iter) {
  leveldb_iter_next(iter->rep);
}

void
ldb_iter_prev(ldb_iter_t *iter) {
  leveldb_iter_prev(iter->rep);
}

ldb_slice_t
ldb_iter_key(const ldb_iter_t *iter) {
  ldb_slice_t key;
  key.data = (void *)leveldb_iter_key(iter->rep, &key.size);
  key.dummy = 0;
  return key;
}

ldb_slice_t
ldb_iter_value(const ldb_iter_t *iter) {
  ldb_slice_t value;
  value.data = (void *)leveldb_iter_value(iter->rep, &value.size);
  value.dummy = 0;
  return value;
}

int
ldb_iter_status(const ldb_iter_t *iter) {
  char *err = NULL;

  leveldb_iter_get_error(iter->rep, &err);

  return handle_error(err);
}

int
ldb_iter_compare(const ldb_iter_t *iter, const ldb_slice_t *key) {
  const ldb_comparator_t *cmp = iter->ucmp;
  ldb_slice_t x = ldb_iter_key(iter);
  return cmp->compare(cmp, &x, key);
}

void
ldb_iter_seek_ge(ldb_iter_t *iter, const ldb_slice_t *target) {
  ldb_iter_seek(iter, target);
}

void
ldb_iter_seek_gt(ldb_iter_t *iter, const ldb_slice_t *target) {
  ldb_iter_seek(iter, target);

  if (ldb_iter_valid(iter)) {
    if (ldb_iter_compare(iter, target) == 0)
      ldb_iter_next(iter);
  }
}

void
ldb_iter_seek_le(ldb_iter_t *iter, const ldb_slice_t *target) {
  ldb_iter_seek(iter, target);

  if (ldb_iter_valid(iter)) {
    if (ldb_iter_compare(iter, target) > 0)
      ldb_iter_prev(iter);
  } else {
    ldb_iter_last(iter);
  }
}

void
ldb_iter_seek_lt(ldb_iter_t *iter, const ldb_slice_t *target) {
  ldb_iter_seek(iter, target);

  if (ldb_iter_valid(iter))
    ldb_iter_prev(iter);
  else
    ldb_iter_last(iter);
}

/*
 * Logging
 */

ldb_logger_t *
ldb_logger_create(void (*logv)(void *, const char *, va_list), void *state) {
  ldb_logger_t *result = safe_malloc(sizeof(ldb_logger_t));

  (void)logv;
  (void)state;

  /* No way to instantiate. */
  result->rep = NULL;

  return result;
}

void
ldb_logger_destroy(ldb_logger_t *logger) {
  safe_free(logger);
}

/*
 * Options
 */

static const ldb_dbopt_t db_options = {
  /* .comparator = */ NULL,
  /* .create_if_missing = */ 0,
  /* .error_if_exists = */ 0,
  /* .paranoid_checks = */ 0,
  /* .info_log = */ NULL,
  /* .write_buffer_size = */ 4 * 1024 * 1024,
  /* .max_open_files = */ 1000,
  /* .block_cache = */ NULL,
  /* .block_size = */ 4 * 1024,
  /* .block_restart_interval = */ 16,
  /* .max_file_size = */ 2 * 1024 * 1024,
  /* .compression = */ LDB_SNAPPY_COMPRESSION,
  /* .reuse_logs = */ 0,
  /* .filter_policy = */ NULL,
  /* .use_mmap = */ 1
};

static const ldb_readopt_t read_options = {
  /* .verify_checksums = */ 0,
  /* .fill_cache = */ 1,
  /* .snapshot = */ NULL
};

static const ldb_writeopt_t write_options = {
  /* .sync = */ 0
};

static const ldb_readopt_t iter_options = {
  /* .verify_checksums = */ 0,
  /* .fill_cache = */ 0,
  /* .snapshot = */ NULL
};

const ldb_dbopt_t *ldb_dbopt_default = &db_options;
const ldb_readopt_t *ldb_readopt_default = &read_options;
const ldb_writeopt_t *ldb_writeopt_default = &write_options;
const ldb_readopt_t *ldb_iteropt_default = &iter_options;

/*
 * Slice
 */

ldb_slice_t
ldb_slice(const void *xp, size_t xn) {
  ldb_slice_t ret;
  ret.data = (void *)xp;
  ret.size = xn;
  ret.dummy = 0;
  return ret;
}

ldb_slice_t
ldb_string(const char *xp) {
  ldb_slice_t ret;
  ret.data = (void *)xp;
  ret.size = strlen(xp);
  ret.dummy = 0;
  return ret;
}

/*
 * Status
 */

static const char *ldb_errmsg[] = {
  /* .LDB_OK = */ "OK",
  /* .LDB_NOTFOUND = */ "NotFound",
  /* .LDB_CORRUPTION = */ "Corruption",
  /* .LDB_NOSUPPORT = */ "Not implemented",
  /* .LDB_INVALID = */ "Invalid argument",
  /* .LDB_IOERR = */ "IO error"
};

const char *
ldb_strerror(int code) {
  if (code < 0)
    code = -code;

  if (code >= (int)lengthof(ldb_errmsg))
    code = -LDB_INVALID;

  return ldb_errmsg[code];
}
