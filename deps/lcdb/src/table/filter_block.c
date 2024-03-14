/*!
 * filter_block.c - filter block builder/reader for lcdb
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

#include "../util/array.h"
#include "../util/bloom.h"
#include "../util/buffer.h"
#include "../util/coding.h"
#include "../util/slice.h"
#include "../util/vector.h"

#include "filter_block.h"

/*
 * Constants
 */

/* Generate new filter every 2KB of data. */
#define LDB_FILTER_BASE_LG 11
#define LDB_FILTER_BASE (1 << LDB_FILTER_BASE_LG)

/*
 * FilterBuilder
 */

ldb_filtergen_t *
ldb_filtergen_create(const ldb_bloom_t *policy) {
  ldb_filtergen_t *fb = ldb_malloc(sizeof(ldb_filtergen_t));
  ldb_filtergen_init(fb, policy);
  return fb;
}

void
ldb_filtergen_destroy(ldb_filtergen_t *fb) {
  ldb_filtergen_clear(fb);
  ldb_free(fb);
}

void
ldb_filtergen_init(ldb_filtergen_t *fb, const ldb_bloom_t *policy) {
  fb->policy = policy;
  fb->tmp_keys = NULL;
  fb->num_keys = 0;

  ldb_buffer_init(&fb->keys);
  ldb_array_init(&fb->start);
  ldb_buffer_init(&fb->result);
  ldb_array_init(&fb->filter_offsets);
}

void
ldb_filtergen_clear(ldb_filtergen_t *fb) {
  if (fb->num_keys > 0)
    ldb_free(fb->tmp_keys);

  ldb_buffer_clear(&fb->keys);
  ldb_array_clear(&fb->start);
  ldb_buffer_clear(&fb->result);
  ldb_array_clear(&fb->filter_offsets);
}

static ldb_slice_t *
ldb_filtergen_alloc(ldb_filtergen_t *fb, size_t num_keys) {
  if (num_keys > fb->num_keys) {
    fb->tmp_keys = ldb_realloc(fb->tmp_keys, num_keys * sizeof(ldb_slice_t));
    fb->num_keys = num_keys;
  }
  return fb->tmp_keys;
}

static void
ldb_filtergen_generate(ldb_filtergen_t *fb) {
  size_t num_keys = fb->start.length;
  ldb_slice_t *tmp_keys;
  size_t i;

  if (num_keys == 0) {
    /* Fast path if there are no keys for this filter. */
    ldb_array_push(&fb->filter_offsets, fb->result.size);
    return;
  }

  /* Make list of keys from flattened key structure. */
  ldb_array_push(&fb->start, fb->keys.size); /* Simplify length computation. */

  tmp_keys = ldb_filtergen_alloc(fb, num_keys);

  for (i = 0; i < num_keys; i++) {
    const uint8_t *base = fb->keys.data + fb->start.items[i];
    size_t length = fb->start.items[i + 1] - fb->start.items[i];

    ldb_slice_set(&tmp_keys[i], base, length);
  }

  /* Generate filter for current set of keys and append to result. */
  ldb_array_push(&fb->filter_offsets, fb->result.size);
  ldb_bloom_build(fb->policy, &fb->result, tmp_keys, num_keys);

  ldb_buffer_reset(&fb->keys);
  ldb_array_reset(&fb->start);
}

void
ldb_filtergen_start_block(ldb_filtergen_t *fb, uint64_t block_offset) {
  uint64_t filter_index = (block_offset / LDB_FILTER_BASE);

  assert(filter_index >= fb->filter_offsets.length);

  while (filter_index > fb->filter_offsets.length)
    ldb_filtergen_generate(fb);
}

void
ldb_filtergen_add_key(ldb_filtergen_t *fb, const ldb_slice_t *key) {
  ldb_array_push(&fb->start, fb->keys.size);
  ldb_buffer_append(&fb->keys, key->data, key->size);
}

ldb_slice_t
ldb_filtergen_finish(ldb_filtergen_t *fb) {
  uint32_t array_offset;
  size_t i;

  if (fb->start.length > 0)
    ldb_filtergen_generate(fb);

  /* Append array of per-filter offsets. */
  array_offset = fb->result.size;

  for (i = 0; i < fb->filter_offsets.length; i++)
    ldb_buffer_fixed32(&fb->result, fb->filter_offsets.items[i]);

  ldb_buffer_fixed32(&fb->result, array_offset);

  /* Save encoding parameter in result. */
  ldb_buffer_push(&fb->result, LDB_FILTER_BASE_LG);

  return fb->result;
}

/*
 * FilterReader
 */

ldb_filter_t *
ldb_filter_create(const ldb_bloom_t *policy,
                  const ldb_slice_t *contents) {
  ldb_filter_t *fr = ldb_malloc(sizeof(ldb_filter_t));
  ldb_filter_init(fr, policy, contents);
  return fr;
}

void
ldb_filter_destroy(ldb_filter_t *fr) {
  ldb_free(fr);
}

void
ldb_filter_init(ldb_filter_t *fr,
                const ldb_bloom_t *policy,
                const ldb_slice_t *contents) {
  size_t n, last_word;

  fr->policy = policy;
  fr->data = NULL;
  fr->offset = NULL;
  fr->num = 0;
  fr->base_lg = 0;

  n = contents->size;

  if (n < 5)
    return; /* 1 byte for base_lg and 4 for start of offset array. */

  fr->base_lg = contents->data[n - 1] & 63;

  last_word = ldb_fixed32_decode(contents->data + n - 5);

  if (last_word > n - 5)
    return;

  fr->data = contents->data;
  fr->offset = fr->data + last_word;
  fr->num = (n - 5 - last_word) / 4;
}

int
ldb_filter_matches(const ldb_filter_t *fr,
                   uint64_t block_offset,
                   const ldb_slice_t *key) {
  uint64_t index = block_offset >> fr->base_lg;

  if (index < fr->num) {
    uint32_t start = ldb_fixed32_decode(fr->offset + index * 4);
    uint32_t limit = ldb_fixed32_decode(fr->offset + index * 4 + 4);

    if (start <= limit && limit <= (size_t)(fr->offset - fr->data)) {
      ldb_slice_t filter;

      ldb_slice_set(&filter, fr->data + start, limit - start);

      return ldb_bloom_match(fr->policy, &filter, key);
    }

    if (start == limit) {
      /* Empty filters do not match any keys. */
      return 0;
    }
  }

  return 1; /* Errors are treated as potential matches. */
}
