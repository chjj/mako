/*!
 * table_builder.c - sorted string table builder for lcdb
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

#include "../util/bloom.h"
#include "../util/buffer.h"
#include "../util/coding.h"
#include "../util/comparator.h"
#include "../util/crc32c.h"
#include "../util/env.h"
#include "../util/internal.h"
#include "../util/options.h"
#include "../util/slice.h"
#include "../util/snappy.h"
#include "../util/status.h"

#include "block_builder.h"
#include "filter_block.h"
#include "format.h"
#include "table_builder.h"

/*
 * Table Builder
 */

struct ldb_tablebuilder_s {
  ldb_dbopt_t options;
  ldb_dbopt_t index_block_options;
  ldb_wfile_t *file;
  uint64_t offset;
  int status;
  ldb_blockbuilder_t data_block;
  ldb_blockbuilder_t index_block;
  ldb_buffer_t last_key;
  int64_t num_entries;
  int closed; /* Either finish() or abandon() has been called. */
  ldb_filterbuilder_t filter_block_;
  ldb_filterbuilder_t *filter_block;

  /* We do not emit the index entry for a block until we have seen the
     first key for the next data block.  This allows us to use shorter
     keys in the index block.  For example, consider a block boundary
     between the keys "the quick brown fox" and "the who".  We can use
     "the r" as the key for the index block entry since it is >= all
     entries in the first block and < all entries in subsequent
     blocks. */
  /* Invariant: tb->pending_index_entry is true only if data_block is empty. */
  int pending_index_entry;
  ldb_blockhandle_t pending_handle; /* Handle to add to index block. */
  ldb_buffer_t compressed_output;
};

static void
ldb_tablebuilder_init(ldb_tablebuilder_t *tb,
                      const ldb_dbopt_t *options,
                      ldb_wfile_t *file) {
  tb->options = *options;
  tb->index_block_options = *options;
  tb->file = file;
  tb->offset = 0;
  tb->status = LDB_OK;

  ldb_blockbuilder_init(&tb->data_block, &tb->options);
  ldb_blockbuilder_init(&tb->index_block, &tb->index_block_options);

  ldb_buffer_init(&tb->last_key);

  tb->num_entries = 0;
  tb->closed = 0;
  tb->filter_block = NULL;
  tb->pending_index_entry = 0;

  ldb_blockhandle_init(&tb->pending_handle);
  ldb_buffer_init(&tb->compressed_output);

  tb->index_block_options.block_restart_interval = 1;

  if (options->filter_policy != NULL) {
    tb->filter_block = &tb->filter_block_;

    ldb_filterbuilder_init(tb->filter_block, options->filter_policy);
    ldb_filterbuilder_start_block(tb->filter_block, 0);
  }
}

static void
ldb_tablebuilder_clear(ldb_tablebuilder_t *tb) {
  assert(tb->closed); /* Catch errors where caller forgot to call finish(). */

  ldb_blockbuilder_clear(&tb->data_block);
  ldb_blockbuilder_clear(&tb->index_block);

  ldb_buffer_clear(&tb->last_key);
  ldb_buffer_clear(&tb->compressed_output);

  if (tb->filter_block != NULL)
    ldb_filterbuilder_clear(tb->filter_block);
}

ldb_tablebuilder_t *
ldb_tablebuilder_create(const ldb_dbopt_t *options, ldb_wfile_t *file) {
  ldb_tablebuilder_t *tb = ldb_malloc(sizeof(ldb_tablebuilder_t));
  ldb_tablebuilder_init(tb, options, file);
  return tb;
}

void
ldb_tablebuilder_destroy(ldb_tablebuilder_t *tb) {
  ldb_tablebuilder_clear(tb);
  ldb_free(tb);
}

int
ldb_tablebuilder_ok(const ldb_tablebuilder_t *tb) {
  return tb->status == LDB_OK;
}

int
ldb_tablebuilder_change_options(ldb_tablebuilder_t *tb,
                                const ldb_dbopt_t *options) {
  /* Note: if more fields are added to Options, update
     this function to catch changes that should not be allowed to
     change in the middle of building a Table. */
  if (options->comparator != tb->options.comparator)
    return LDB_INVALID; /* "changing comparator while building table" */

  /* Note that any live BlockBuilders point to tb->options and therefore
     will automatically pick up the updated options. */
  tb->options = *options;
  tb->index_block_options = *options;
  tb->index_block_options.block_restart_interval = 1;

  return LDB_OK;
}

static void
ldb_tablebuilder_write_raw_block(ldb_tablebuilder_t *tb,
                                 const ldb_slice_t *block_contents,
                                 enum ldb_compression type,
                                 ldb_blockhandle_t *handle) {
  handle->offset = tb->offset;
  handle->size = block_contents->size;

  tb->status = ldb_wfile_append(tb->file, block_contents);

  if (tb->status == LDB_OK) {
    uint8_t trailer[LDB_BLOCK_TRAILER_SIZE];
    ldb_slice_t trail;
    uint32_t crc;

    trailer[0] = type;

    crc = ldb_crc32c_value(block_contents->data, block_contents->size);
    crc = ldb_crc32c_extend(crc, trailer, 1); /* Extend crc to cover block type. */

    ldb_fixed32_write(trailer + 1, ldb_crc32c_mask(crc));

    ldb_slice_set(&trail, trailer, sizeof(trailer));

    tb->status = ldb_wfile_append(tb->file, &trail);

    if (tb->status == LDB_OK)
      tb->offset += block_contents->size + sizeof(trailer);
  }
}

static void
ldb_tablebuilder_write_block(ldb_tablebuilder_t *tb,
                             ldb_blockbuilder_t *block,
                             ldb_blockhandle_t *handle) {
  /* File format contains a sequence of blocks where each block has:
   *
   *    block_data: uint8[n]
   *    type: uint8
   *    crc: uint32
   */
  ldb_slice_t raw, block_contents;
  enum ldb_compression type;

  assert(ldb_tablebuilder_ok(tb));

  raw = ldb_blockbuilder_finish(block);
  type = tb->options.compression;

  switch (type) {
    case LDB_NO_COMPRESSION: {
      block_contents = raw;
      break;
    }

    case LDB_SNAPPY_COMPRESSION: {
      ldb_buffer_t *compressed = &tb->compressed_output;
      size_t max;

      if (!snappy_encode_size(&max, raw.size))
        abort(); /* LCOV_EXCL_LINE */

      ldb_buffer_grow(compressed, max);

      compressed->size = snappy_encode(compressed->data,
                                       raw.data, raw.size);

      if (compressed->size < raw.size - (raw.size / 8)) {
        block_contents = *compressed;
      } else {
        /* Snappy not supported, or compressed less than
           12.5%, so just store uncompressed form. */
        block_contents = raw;
        type = LDB_NO_COMPRESSION;
      }

      break;
    }

    default: {
      abort(); /* LCOV_EXCL_LINE */
      break;
    }
  }

  ldb_tablebuilder_write_raw_block(tb, &block_contents, type, handle);

  /* ldb_buffer_reset(&tb->compressed_output); */

  ldb_blockbuilder_reset(block);
}

void
ldb_tablebuilder_add(ldb_tablebuilder_t *tb,
                     const ldb_slice_t *key,
                     const ldb_slice_t *value) {
  size_t estimated_block_size;

  assert(!tb->closed);

  if (!ldb_tablebuilder_ok(tb))
    return;

  if (tb->num_entries > 0)
    assert(ldb_compare(tb->options.comparator, key, &tb->last_key) > 0);

  if (tb->pending_index_entry) {
    uint8_t tmp[LDB_BLOCKHANDLE_MAX];
    ldb_buffer_t handle_encoding;

    assert(ldb_blockbuilder_empty(&tb->data_block));

    ldb_shortest_separator(tb->options.comparator, &tb->last_key, key);
    ldb_buffer_rwset(&handle_encoding, tmp, sizeof(tmp));
    ldb_blockhandle_export(&handle_encoding, &tb->pending_handle);
    ldb_blockbuilder_add(&tb->index_block, &tb->last_key, &handle_encoding);
    tb->pending_index_entry = 0;
  }

  if (tb->filter_block != NULL)
    ldb_filterbuilder_add_key(tb->filter_block, key);

  /* ldb_buffer_set(&tb->last_key, key->data, key->size); */
  ldb_buffer_copy(&tb->last_key, key);

  tb->num_entries++;

  ldb_blockbuilder_add(&tb->data_block, key, value);

  estimated_block_size = ldb_blockbuilder_size_estimate(&tb->data_block);

  if (estimated_block_size >= tb->options.block_size)
    ldb_tablebuilder_flush(tb);
}

void
ldb_tablebuilder_flush(ldb_tablebuilder_t *tb) {
  assert(!tb->closed);

  if (!ldb_tablebuilder_ok(tb))
    return;

  if (ldb_blockbuilder_empty(&tb->data_block))
    return;

  assert(!tb->pending_index_entry);

  ldb_tablebuilder_write_block(tb, &tb->data_block, &tb->pending_handle);

  if (ldb_tablebuilder_ok(tb)) {
    tb->pending_index_entry = 1;
    tb->status = ldb_wfile_flush(tb->file);
  }

  if (tb->filter_block != NULL)
    ldb_filterbuilder_start_block(tb->filter_block, tb->offset);
}

int
ldb_tablebuilder_status(const ldb_tablebuilder_t *tb) {
  return tb->status;
}

int
ldb_tablebuilder_finish(ldb_tablebuilder_t *tb) {
  ldb_blockhandle_t metaindex_handle = {0, 0};
  ldb_blockhandle_t index_handle = {0, 0};
  ldb_blockhandle_t filter_handle;

  ldb_tablebuilder_flush(tb);

  assert(!tb->closed);

  tb->closed = 1;

  /* Write filter block. */
  if (ldb_tablebuilder_ok(tb) && tb->filter_block != NULL) {
    ldb_slice_t contents = ldb_filterbuilder_finish(tb->filter_block);

    ldb_tablebuilder_write_raw_block(tb,
                                     &contents,
                                     LDB_NO_COMPRESSION,
                                     &filter_handle);
  }

  /* Write metaindex block. */
  if (ldb_tablebuilder_ok(tb)) {
    ldb_blockbuilder_t metaindex_block;

    ldb_blockbuilder_init(&metaindex_block, &tb->options);

    if (tb->filter_block != NULL) {
      /* Add mapping from "filter.Name" to location of filter data. */
      uint8_t tmp[LDB_BLOCKHANDLE_MAX];
      ldb_buffer_t handle_encoding;
      ldb_slice_t key;
      char name[72];

      if (!ldb_bloom_name(name, sizeof(name), tb->options.filter_policy)) {
        ldb_blockbuilder_clear(&metaindex_block);
        return LDB_INVALID;
      }

      ldb_slice_set_str(&key, name);
      ldb_buffer_rwset(&handle_encoding, tmp, sizeof(tmp));
      ldb_blockhandle_export(&handle_encoding, &filter_handle);
      ldb_blockbuilder_add(&metaindex_block, &key, &handle_encoding);
    }

    ldb_tablebuilder_write_block(tb, &metaindex_block, &metaindex_handle);

    ldb_blockbuilder_clear(&metaindex_block);
  }

  /* Write index block. */
  if (ldb_tablebuilder_ok(tb)) {
    if (tb->pending_index_entry) {
      uint8_t tmp[LDB_BLOCKHANDLE_MAX];
      ldb_buffer_t handle_encoding;

      ldb_short_successor(tb->options.comparator, &tb->last_key);
      ldb_buffer_rwset(&handle_encoding, tmp, sizeof(tmp));
      ldb_blockhandle_export(&handle_encoding, &tb->pending_handle);
      ldb_blockbuilder_add(&tb->index_block, &tb->last_key, &handle_encoding);
      tb->pending_index_entry = 0;
    }

    ldb_tablebuilder_write_block(tb, &tb->index_block, &index_handle);
  }

  /* Write footer. */
  if (ldb_tablebuilder_ok(tb)) {
    uint8_t tmp[LDB_FOOTER_SIZE];
    ldb_buffer_t footer_encoding;
    ldb_footer_t footer;

    footer.metaindex_handle = metaindex_handle;
    footer.index_handle = index_handle;

    ldb_buffer_rwset(&footer_encoding, tmp, sizeof(tmp));
    ldb_footer_export(&footer_encoding, &footer);

    tb->status = ldb_wfile_append(tb->file, &footer_encoding);

    if (tb->status == LDB_OK)
      tb->offset += footer_encoding.size;
  }

  return tb->status;
}

void
ldb_tablebuilder_abandon(ldb_tablebuilder_t *tb) {
  assert(!tb->closed);
  tb->closed = 1;
}

uint64_t
ldb_tablebuilder_num_entries(const ldb_tablebuilder_t *tb) {
  return tb->num_entries;
}

uint64_t
ldb_tablebuilder_file_size(const ldb_tablebuilder_t *tb) {
  return tb->offset;
}
