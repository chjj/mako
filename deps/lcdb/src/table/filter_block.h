/*!
 * filter_block.h - filter block builder/reader for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on google/leveldb:
 *   Copyright (c) 2011, The LevelDB Authors. All rights reserved.
 *   https://github.com/google/leveldb
 *
 * See LICENSE for more information.
 */

#ifndef LDB_FILTER_BLOCK_H
#define LDB_FILTER_BLOCK_H

#include <stddef.h>
#include <stdint.h>

#include "../util/types.h"

/*
 * Types
 */

struct ldb_bloom_s;

/* A filter block builder is used to construct all of the filters for a
 * particular Table. It generates a single string which is stored as
 * a special block in the table.
 *
 * The sequence of calls to filter block builder must match the regexp:
 *     (start_block add_key*)* finish
 */
typedef struct ldb_filtergen_s {
  const ldb_bloom_t *policy;
  ldb_slice_t *tmp_keys;      /* ldb_bloom_build() argument. */
  size_t num_keys;            /* Size tracking for tmp_keys. */
  ldb_buffer_t keys;          /* Flattened key contents. */
  ldb_array_t start;          /* Starting index in keys of each key (size_t). */
  ldb_buffer_t result;        /* Filter data computed so far. */
  ldb_array_t filter_offsets; /* Filter offsets (uint32_t). */
} ldb_filtergen_t;

typedef struct ldb_filter_s {
  const struct ldb_bloom_s *policy;
  const uint8_t *data;   /* Pointer to filter data (block-start). */
  const uint8_t *offset; /* Pointer to beginning of offset array (block-end). */
  size_t num;            /* Number of entries in offset array. */
  size_t base_lg;        /* Encoding parameter (see LDB_FILTER_BASE_LG). */
} ldb_filter_t;

/*
 * FilterBuilder
 */

ldb_filtergen_t *
ldb_filtergen_create(const ldb_bloom_t *policy);

void
ldb_filtergen_destroy(ldb_filtergen_t *fb);

void
ldb_filtergen_init(ldb_filtergen_t *fb,
                   const struct ldb_bloom_s *policy);

void
ldb_filtergen_clear(ldb_filtergen_t *fb);

void
ldb_filtergen_start_block(ldb_filtergen_t *fb, uint64_t block_offset);

void
ldb_filtergen_add_key(ldb_filtergen_t *fb, const ldb_slice_t *key);

ldb_slice_t
ldb_filtergen_finish(ldb_filtergen_t *fb);

/*
 * FilterReader
 */

ldb_filter_t *
ldb_filter_create(const ldb_bloom_t *policy,
                  const ldb_slice_t *contents);

void
ldb_filter_destroy(ldb_filter_t *fr);

/* REQUIRES: "contents" and *policy must stay live while *this is live. */
void
ldb_filter_init(ldb_filter_t *fr,
                const struct ldb_bloom_s *policy,
                const ldb_slice_t *contents);

int
ldb_filter_matches(const ldb_filter_t *fr,
                   uint64_t block_offset,
                   const ldb_slice_t *key);

#endif /* LDB_FILTER_BLOCK_H */
