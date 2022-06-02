/*!
 * block_builder.c - block builder for lcdb
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
#include "../util/buffer.h"
#include "../util/comparator.h"
#include "../util/internal.h"
#include "../util/options.h"
#include "../util/slice.h"
#include "../util/vector.h"

#include "block_builder.h"

/* BlockBuilder generates blocks where keys are prefix-compressed:
 *
 * When we store a key, we drop the prefix shared with the previous
 * string. This helps reduce the space requirement significantly.
 * Furthermore, once every K keys, we do not apply the prefix
 * compression and store the entire key. We call this a "restart
 * point". The tail end of the block stores the offsets of all of the
 * restart points, and can be used to do a binary search when looking
 * for a particular key. Values are stored as-is (without compression)
 * immediately following the corresponding key.
 *
 * An entry for a particular key-value pair has the form:
 *     shared_bytes: varint32
 *     unshared_bytes: varint32
 *     value_length: varint32
 *     key_delta: char[unshared_bytes]
 *     value: char[value_length]
 * shared_bytes == 0 for restart points.
 *
 * The trailer of the block has the form:
 *     restarts: uint32[num_restarts]
 *     num_restarts: uint32
 * restarts[i] contains the offset within the block of the ith restart point.
 */

/*
 * BlockBuilder
 */

void
ldb_blockgen_init(ldb_blockgen_t *bb, const ldb_dbopt_t *options) {
  assert(options->block_restart_interval >= 1);

  bb->options = options;
  bb->counter = 0;
  bb->finished = 0;

  ldb_buffer_init(&bb->buffer);
  ldb_array_init(&bb->restarts);
  ldb_buffer_init(&bb->last_key);

  ldb_array_push(&bb->restarts, 0); /* First restart point is at offset 0. */
}

void
ldb_blockgen_clear(ldb_blockgen_t *bb) {
  ldb_buffer_clear(&bb->buffer);
  ldb_array_clear(&bb->restarts);
  ldb_buffer_clear(&bb->last_key);
}

void
ldb_blockgen_reset(ldb_blockgen_t *bb) {
  ldb_buffer_reset(&bb->buffer);
  ldb_array_reset(&bb->restarts);

  ldb_array_push(&bb->restarts, 0); /* First restart point is at offset 0. */

  bb->counter = 0;
  bb->finished = 0;

  ldb_buffer_reset(&bb->last_key);
}

void
ldb_blockgen_add(ldb_blockgen_t *bb,
                 const ldb_slice_t *key,
                 const ldb_slice_t *value) {
  const ldb_comparator_t *comparator = bb->options->comparator;
  const uint8_t *key_offset = key->data;
  ldb_slice_t last = bb->last_key;
  size_t shared, non_shared;

  assert(!bb->finished);
  assert(bb->counter <= bb->options->block_restart_interval);
  assert(ldb_blockgen_empty(bb) || ldb_compare(comparator, key, &last) > 0);

  (void)comparator;

  shared = 0;

  if (bb->counter < bb->options->block_restart_interval) {
    /* See how much sharing to do with previous string. */
    size_t min_length = LDB_MIN(last.size, key->size);

    while (shared < min_length && last.data[shared] == key->data[shared])
      shared++;
  } else {
    /* Restart compression. */
    ldb_array_push(&bb->restarts, bb->buffer.size);
    bb->counter = 0;
  }

  if (shared > 0)
    key_offset += shared;

  non_shared = key->size - shared;

  /* Add "<shared><non_shared><value_size>" to buffer. */
  ldb_buffer_varint32(&bb->buffer, shared);
  ldb_buffer_varint32(&bb->buffer, non_shared);
  ldb_buffer_varint32(&bb->buffer, value->size);

  /* Add string delta to buffer followed by value. */
  ldb_buffer_append(&bb->buffer, key_offset, non_shared);
  ldb_buffer_append(&bb->buffer, value->data, value->size);

  /* Update state. */
  ldb_buffer_resize(&bb->last_key, shared);
  ldb_buffer_append(&bb->last_key, key_offset, non_shared);
  assert(ldb_slice_equal(&bb->last_key, key));
  bb->counter++;
}

ldb_slice_t
ldb_blockgen_finish(ldb_blockgen_t *bb) {
  /* Append restart array. */
  size_t i;

  for (i = 0; i < bb->restarts.length; i++)
    ldb_buffer_fixed32(&bb->buffer, bb->restarts.items[i]);

  ldb_buffer_fixed32(&bb->buffer, bb->restarts.length);

  bb->finished = 1;

  return bb->buffer;
}

size_t
ldb_blockgen_size_estimate(const ldb_blockgen_t *bb) {
  return (bb->buffer.size +                        /* Raw data buffer */
          bb->restarts.length * sizeof(uint32_t) + /* Restart array */
          sizeof(uint32_t));                       /* Restart array length */
}
