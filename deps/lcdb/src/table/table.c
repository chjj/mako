/*!
 * table.c - sorted string table for lcdb
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
#include <stddef.h>
#include <stdint.h>

#include "../util/bloom.h"
#include "../util/cache.h"
#include "../util/coding.h"
#include "../util/comparator.h"
#include "../util/env.h"
#include "../util/internal.h"
#include "../util/options.h"
#include "../util/slice.h"
#include "../util/status.h"

#include "block.h"
#include "filter_block.h"
#include "format.h"
#include "iterator.h"
#include "table.h"
#include "two_level_iterator.h"

/*
 * Table
 */

struct ldb_table_s {
  ldb_dbopt_t options;
  int status;
  ldb_rfile_t *file;
  uint64_t cache_id;
  ldb_filter_t *filter;
  const uint8_t *filter_data;
  ldb_handle_t metaindex_handle; /* Handle to metaindex_block:
                                    saved from footer. */
  ldb_block_t *index_block;
};

static void
ldb_table_read_filter(ldb_table_t *table,
                      const ldb_slice_t *filter_handle_value) {
  ldb_readopt_t opt = *ldb_readopt_default;
  ldb_handle_t filter_handle;
  ldb_contents_t block;
  int rc;

  if (!ldb_handle_import(&filter_handle, filter_handle_value))
    return;

  /* We might want to unify with read_block() if we start
     requiring checksum verification in table_open(). */
  if (table->options.paranoid_checks)
    opt.verify_checksums = 1;

  rc = ldb_read_block(&block,
                      table->file,
                      &opt,
                      &filter_handle);

  if (rc != LDB_OK)
    return;

  if (block.heap_allocated)
    table->filter_data = block.data.data; /* Will need to delete later. */

  table->filter = ldb_filter_create(table->options.filter_policy, &block.data);
}

static void
ldb_table_read_meta(ldb_table_t *table, const ldb_footer_t *footer) {
  ldb_readopt_t opt = *ldb_readopt_default;
  ldb_contents_t contents;
  ldb_block_t *meta;
  ldb_iter_t *iter;
  ldb_slice_t key;
  char name[72];
  int rc;

  if (table->options.filter_policy == NULL)
    return; /* Do not need any metadata. */

  if (table->options.paranoid_checks)
    opt.verify_checksums = 1;

  if (!ldb_bloom_name(name, sizeof(name), table->options.filter_policy))
    return;

  rc = ldb_read_block(&contents,
                      table->file,
                      &opt,
                      &footer->metaindex_handle);

  if (rc != LDB_OK) {
    /* Do not propagate errors since meta info is not needed for operation. */
    return;
  }

  meta = ldb_block_create(&contents);
  iter = ldb_blockiter_create(meta, ldb_bytewise_comparator);

  ldb_slice_set_str(&key, name);
  ldb_iter_seek(iter, &key);

  if (ldb_iter_valid(iter)) {
    ldb_slice_t iter_key = ldb_iter_key(iter);

    if (ldb_slice_equal(&iter_key, &key)) {
      ldb_slice_t iter_value = ldb_iter_value(iter);
      ldb_table_read_filter(table, &iter_value);
    }
  }

  ldb_iter_destroy(iter);
  ldb_block_destroy(meta);
}

int
ldb_table_open(const ldb_dbopt_t *options,
               ldb_rfile_t *file,
               uint64_t size,
               ldb_table_t **table) {
  ldb_readopt_t opt = *ldb_readopt_default;
  uint8_t buf[LDB_FOOTER_SIZE];
  ldb_contents_t contents;
  ldb_footer_t footer;
  ldb_slice_t input;
  int rc;

  *table = NULL;

  if (size < LDB_FOOTER_SIZE)
    return LDB_CORRUPTION; /* "file is too short to be an sstable" */

  rc = ldb_rfile_pread(file,
                       &input,
                       buf,
                       LDB_FOOTER_SIZE,
                       size - LDB_FOOTER_SIZE);

  if (rc != LDB_OK)
    return rc;

  if (!ldb_footer_import(&footer, &input))
    return LDB_CORRUPTION;

  /* Read the index block. */
  if (options->paranoid_checks)
    opt.verify_checksums = 1;

  rc = ldb_read_block(&contents,
                      file,
                      &opt,
                      &footer.index_handle);

  if (rc == LDB_OK) {
    /* We've successfully read the footer and the
       index block: we're ready to serve requests. */
    ldb_block_t *index_block = ldb_block_create(&contents);
    ldb_table_t *tbl = ldb_malloc(sizeof(ldb_table_t));

    tbl->options = *options;
    tbl->status = LDB_OK;
    tbl->file = file;
    tbl->cache_id = 0;
    tbl->filter = NULL;
    tbl->filter_data = NULL;
    tbl->metaindex_handle = footer.metaindex_handle;
    tbl->index_block = index_block;

    if (options->block_cache != NULL)
      tbl->cache_id = ldb_lru_id(options->block_cache);

    ldb_table_read_meta(tbl, &footer);

    *table = tbl;
  }

  return rc;
}

void
ldb_table_destroy(ldb_table_t *table) {
  if (table->filter != NULL)
    ldb_filter_destroy(table->filter);

  if (table->filter_data != NULL)
    ldb_free((void *)table->filter_data);

  ldb_block_destroy(table->index_block);

  ldb_free(table);
}

static void
delete_block(void *arg, void *ignored) {
  ldb_block_t *block = (ldb_block_t *)arg;
  (void)ignored;
  ldb_block_destroy(block);
}

static void
delete_cached_block(const ldb_slice_t *key, void *value) {
  ldb_block_t *block = (ldb_block_t *)value;
  (void)key;
  ldb_block_destroy(block);
}

static void
release_block(void *arg, void *h) {
  ldb_lru_t *cache = (ldb_lru_t *)arg;
  ldb_entry_t *handle = (ldb_entry_t *)h;

  ldb_lru_release(cache, handle);
}

/* Convert an index iterator value (i.e., an encoded BlockHandle)
   into an iterator over the contents of the corresponding block. */
static ldb_iter_t *
ldb_table_blockreader(void *arg,
                      const ldb_readopt_t *options,
                      const ldb_slice_t *index_value) {
  ldb_table_t *table = (ldb_table_t *)arg;
  ldb_lru_t *block_cache = table->options.block_cache;
  ldb_entry_t *cache_handle = NULL;
  ldb_block_t *block = NULL;
  ldb_handle_t handle;
  ldb_iter_t *iter;
  int rc = LDB_OK;

  /* We intentionally allow extra stuff in index_value so that we
     can add more features in the future. */

  if (!ldb_handle_import(&handle, index_value))
    rc = LDB_CORRUPTION;

  if (rc == LDB_OK) {
    ldb_contents_t contents;

    if (block_cache != NULL) {
      uint8_t cache_key_buffer[16];
      ldb_slice_t key;

      ldb_fixed64_write(cache_key_buffer + 0, table->cache_id);
      ldb_fixed64_write(cache_key_buffer + 8, handle.offset);

      ldb_slice_set(&key, cache_key_buffer, sizeof(cache_key_buffer));

      cache_handle = ldb_lru_lookup(block_cache, &key);

      if (cache_handle != NULL) {
        block = (ldb_block_t *)ldb_lru_value(cache_handle);
      } else {
        rc = ldb_read_block(&contents, table->file, options, &handle);

        if (rc == LDB_OK) {
          block = ldb_block_create(&contents);

          if (contents.cachable && options->fill_cache) {
            cache_handle = ldb_lru_insert(block_cache,
                                          &key,
                                          block,
                                          block->size,
                                          &delete_cached_block);
          }
        }
      }
    } else {
      rc = ldb_read_block(&contents, table->file, options, &handle);

      if (rc == LDB_OK)
        block = ldb_block_create(&contents);
    }
  }

  if (block != NULL) {
    iter = ldb_blockiter_create(block, table->options.comparator);

    if (cache_handle == NULL) {
      ldb_iter_register_cleanup(iter, &delete_block, block, NULL);
    } else {
      ldb_iter_register_cleanup(iter, &release_block, block_cache,
                                                      cache_handle);
    }
  } else {
    iter = ldb_emptyiter_create(rc);
  }

  return iter;
}

ldb_iter_t *
ldb_tableiter_create(const ldb_table_t *table, const ldb_readopt_t *options) {
  ldb_iter_t *iter = ldb_blockiter_create(table->index_block,
                                          table->options.comparator);

  return ldb_twoiter_create(iter,
                            &ldb_table_blockreader,
                            (void *)table,
                            options);
}

int
ldb_table_internal_get(ldb_table_t *table,
                       const ldb_readopt_t *options,
                       const ldb_slice_t *k,
                       void *arg,
                       void (*handle_result)(void *,
                                             const ldb_slice_t *,
                                             const ldb_slice_t *)) {
  ldb_iter_t *index_iter;
  int rc = LDB_OK;

  index_iter = ldb_blockiter_create(table->index_block,
                                    table->options.comparator);

  ldb_iter_seek(index_iter, k);

  if (ldb_iter_valid(index_iter)) {
    ldb_slice_t iter_value = ldb_iter_value(index_iter);
    ldb_filter_t *filter = table->filter;
    ldb_handle_t handle;

    if (filter != NULL &&
        ldb_handle_import(&handle, &iter_value) &&
        !ldb_filter_matches(filter, handle.offset, k)) {
      /* Not found. */
    } else {
      ldb_iter_t *block_iter = ldb_table_blockreader(table,
                                                     options,
                                                     &iter_value);

      ldb_iter_seek(block_iter, k);

      if (ldb_iter_valid(block_iter)) {
        ldb_slice_t block_iter_key = ldb_iter_key(block_iter);
        ldb_slice_t block_iter_value = ldb_iter_value(block_iter);

        (*handle_result)(arg, &block_iter_key, &block_iter_value);
      }

      rc = ldb_iter_status(block_iter);

      ldb_iter_destroy(block_iter);
    }
  }

  if (rc == LDB_OK)
    rc = ldb_iter_status(index_iter);

  ldb_iter_destroy(index_iter);

  return rc;
}

uint64_t
ldb_table_approximate_offset(const ldb_table_t *table,
                             const ldb_slice_t *key) {
  ldb_iter_t *index_iter;
  uint64_t result;

  index_iter = ldb_blockiter_create(table->index_block,
                                    table->options.comparator);

  ldb_iter_seek(index_iter, key);

  if (ldb_iter_valid(index_iter)) {
    ldb_slice_t input = ldb_iter_value(index_iter);
    ldb_handle_t handle;

    if (ldb_handle_import(&handle, &input)) {
      result = handle.offset;
    } else {
      /* Strange: we can't decode the block handle in the index block.
         We'll just return the offset of the metaindex block, which is
         close to the whole file size for this case. */
      result = table->metaindex_handle.offset;
    }
  } else {
    /* key is past the last key in the file. Approximate the offset
       by returning the offset of the metaindex block (which is
       right near the end of the file). */
    result = table->metaindex_handle.offset;
  }

  ldb_iter_destroy(index_iter);

  return result;
}
