/*!
 * table_cache.c - sstable cache for lcdb
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
#include <stdint.h>
#include <stdlib.h>

#include "table/iterator.h"
#include "table/table.h"

#include "util/cache.h"
#include "util/coding.h"
#include "util/env.h"
#include "util/internal.h"
#include "util/options.h"
#include "util/slice.h"
#include "util/status.h"

#include "filename.h"
#include "table_cache.h"

/*
 * Types
 */

struct ldb_tcache_s {
  const char *prefix;
  const ldb_dbopt_t *options;
  ldb_lru_t *lru;
};

typedef struct ldb_entry_s {
  ldb_rfile_t *file;
  ldb_table_t *table;
} ldb_entry_t;

/*
 * Helpers
 */

static void
delete_entry(const ldb_slice_t *key, void *value) {
  ldb_entry_t *entry = (ldb_entry_t *)value;

  (void)key;

  ldb_table_destroy(entry->table);
  ldb_rfile_destroy(entry->file);
  ldb_free(entry);
}

static void
unref_entry(void *arg1, void *arg2) {
  ldb_lru_t *lru = (ldb_lru_t *)arg1;
  ldb_lruhandle_t *h = (ldb_lruhandle_t *)arg2;

  ldb_lru_release(lru, h);
}

/*
 * TableCache
 */

ldb_tcache_t *
ldb_tcache_create(const char *prefix, const ldb_dbopt_t *options, int entries) {
  ldb_tcache_t *cache = ldb_malloc(sizeof(ldb_tcache_t));

  cache->prefix = prefix;
  cache->options = options;
  cache->lru = ldb_lru_create(entries);

  return cache;
}

void
ldb_tcache_destroy(ldb_tcache_t *cache) {
  ldb_lru_destroy(cache->lru);
  ldb_free(cache);
}

static int
find_table(ldb_tcache_t *cache,
           uint64_t file_number,
           uint64_t file_size,
           ldb_lruhandle_t **handle) {
  ldb_slice_t key;
  int rc = LDB_OK;
  uint8_t buf[8];

  ldb_fixed64_write(buf, file_number);

  ldb_slice_set(&key, buf, sizeof(buf));

  *handle = ldb_lru_lookup(cache->lru, &key);

  if (*handle == NULL) {
    int use_mmap = cache->options->use_mmap;
    char fname[LDB_PATH_MAX];
    ldb_rfile_t *file = NULL;
    ldb_table_t *table = NULL;

    if (!ldb_table_filename(fname, sizeof(fname), cache->prefix, file_number))
      return LDB_INVALID;

    rc = ldb_randfile_create(fname, &file, use_mmap);

    if (rc != LDB_OK) {
      if (!ldb_sstable_filename(fname, sizeof(fname), cache->prefix,
                                                      file_number)) {
        return LDB_INVALID;
      }

      if (ldb_randfile_create(fname, &file, use_mmap) == LDB_OK)
        rc = LDB_OK;
    }

    if (rc == LDB_OK)
      rc = ldb_table_open(cache->options, file, file_size, &table);

    if (rc != LDB_OK) {
      assert(table == NULL);

      ldb_rfile_destroy(file);

      /* We do not cache error results so that if the error is transient,
         or somebody repairs the file, we recover automatically. */
    } else {
      ldb_entry_t *entry = ldb_malloc(sizeof(ldb_entry_t));

      entry->file = file;
      entry->table = table;

      *handle = ldb_lru_insert(cache->lru, &key, entry, 1, &delete_entry);
    }
  }

  return rc;
}

ldb_iter_t *
ldb_tcache_iterate(ldb_tcache_t *cache,
                   const ldb_readopt_t *options,
                   uint64_t file_number,
                   uint64_t file_size,
                   ldb_table_t **tableptr) {
  ldb_lruhandle_t *handle = NULL;
  ldb_table_t *table;
  ldb_iter_t *result;
  int rc;

  if (tableptr != NULL)
    *tableptr = NULL;

  rc = find_table(cache, file_number, file_size, &handle);

  if (rc != LDB_OK)
    return ldb_emptyiter_create(rc);

  table = ((ldb_entry_t *)ldb_lru_value(handle))->table;
  result = ldb_tableiter_create(table, options);

  ldb_iter_register_cleanup(result, &unref_entry, cache->lru, handle);

  if (tableptr != NULL)
    *tableptr = table;

  return result;
}

int
ldb_tcache_get(ldb_tcache_t *cache,
               const ldb_readopt_t *options,
               uint64_t file_number,
               uint64_t file_size,
               const ldb_slice_t *k,
               void *arg,
               void (*handle_result)(void *,
                                     const ldb_slice_t *,
                                     const ldb_slice_t *)) {
  ldb_lruhandle_t *handle = NULL;
  int rc;

  rc = find_table(cache, file_number, file_size, &handle);

  if (rc == LDB_OK) {
    ldb_table_t *table = ((ldb_entry_t *)ldb_lru_value(handle))->table;

    rc = ldb_table_internal_get(table, options, k, arg, handle_result);

    ldb_lru_release(cache->lru, handle);
  }

  return rc;
}

void
ldb_tcache_evict(ldb_tcache_t *cache, uint64_t file_number) {
  ldb_slice_t key;
  uint8_t buf[8];

  ldb_fixed64_write(buf, file_number);
  ldb_slice_set(&key, buf, sizeof(buf));

  ldb_lru_erase(cache->lru, &key);
}
