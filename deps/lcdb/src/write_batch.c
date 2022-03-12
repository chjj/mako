/*!
 * write_batch.c - write batch for lcdb
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
#include <string.h>

#include "util/buffer.h"
#include "util/coding.h"
#include "util/internal.h"
#include "util/slice.h"
#include "util/status.h"

#include "dbformat.h"
#include "memtable.h"
#include "write_batch.h"

/* ldb_batch_t::rep :=
 *    sequence: fixed64
 *    count: fixed32
 *    data: record[count]
 * record :=
 *    LDB_TYPE_VALUE varstring varstring |
 *    LDB_TYPE_DELETION varstring
 * varstring :=
 *    len: varint32
 *    data: uint8[len]
 */

/*
 * Constants
 */

/* Header has an 8-byte sequence number followed by a 4-byte count. */
#define LDB_HEADER 12

/*
 * Batch
 */

ldb_batch_t *
ldb_batch_create(void) {
  ldb_batch_t *batch = ldb_malloc(sizeof(ldb_batch_t));
  ldb_batch_init(batch);
  return batch;
}

void
ldb_batch_destroy(ldb_batch_t *batch) {
  ldb_batch_clear(batch);
  ldb_free(batch);
}

void
ldb_batch_init(ldb_batch_t *batch) {
  ldb_buffer_init(&batch->rep);
  ldb_batch_reset(batch);
}

void
ldb_batch_clear(ldb_batch_t *batch) {
  ldb_buffer_clear(&batch->rep);
}

void
ldb_batch_reset(ldb_batch_t *batch) {
  ldb_buffer_resize(&batch->rep, LDB_HEADER);

  memset(batch->rep.data, 0, LDB_HEADER);
}

size_t
ldb_batch_approximate_size(const ldb_batch_t *batch) {
  return batch->rep.size;
}

int
ldb_batch_iterate(const ldb_batch_t *batch, ldb_handler_t *handler) {
  ldb_slice_t input = batch->rep;
  ldb_slice_t key, value;
  int found = 0;

  if (input.size < LDB_HEADER)
    return LDB_CORRUPTION; /* "malformed WriteBatch (too small)" */

  ldb_slice_eat(&input, LDB_HEADER);

  while (input.size > 0) {
    int tag = input.data[0];

    ldb_slice_eat(&input, 1);

    found++;

    switch (tag) {
      case LDB_TYPE_VALUE: {
        if (!ldb_slice_slurp(&key, &input))
          return LDB_CORRUPTION; /* "bad WriteBatch Put" */

        if (!ldb_slice_slurp(&value, &input))
          return LDB_CORRUPTION; /* "bad WriteBatch Put" */

        handler->put(handler, &key, &value);

        break;
      }

      case LDB_TYPE_DELETION: {
        if (!ldb_slice_slurp(&key, &input))
          return LDB_CORRUPTION; /* "bad WriteBatch Delete" */

        handler->del(handler, &key);

        break;
      }

      default: {
        return LDB_CORRUPTION; /* "unknown WriteBatch tag" */
      }
    }
  }

  if (found != ldb_batch_count(batch))
    return LDB_CORRUPTION; /* "WriteBatch has wrong count" */

  return LDB_OK;
}

int
ldb_batch_count(const ldb_batch_t *batch) {
  return ldb_fixed32_decode(batch->rep.data + 8);
}

void
ldb_batch_set_count(ldb_batch_t *batch, int count) {
  ldb_fixed32_write(batch->rep.data + 8, count);
}

ldb_seqnum_t
ldb_batch_sequence(const ldb_batch_t *batch) {
  return ldb_fixed64_decode(batch->rep.data);
}

void
ldb_batch_set_sequence(ldb_batch_t *batch, ldb_seqnum_t seq) {
  ldb_fixed64_write(batch->rep.data, seq);
}

void
ldb_batch_put(ldb_batch_t *batch,
              const ldb_slice_t *key,
              const ldb_slice_t *value) {
  ldb_batch_set_count(batch, ldb_batch_count(batch) + 1);
  ldb_buffer_push(&batch->rep, LDB_TYPE_VALUE);
  ldb_slice_export(&batch->rep, key);
  ldb_slice_export(&batch->rep, value);
}

void
ldb_batch_del(ldb_batch_t *batch, const ldb_slice_t *key) {
  ldb_batch_set_count(batch, ldb_batch_count(batch) + 1);
  ldb_buffer_push(&batch->rep, LDB_TYPE_DELETION);
  ldb_slice_export(&batch->rep, key);
}

void
ldb_batch_append(ldb_batch_t *dst, const ldb_batch_t *src) {
  assert(src->rep.size >= LDB_HEADER);

  ldb_batch_set_count(dst, ldb_batch_count(dst) + ldb_batch_count(src));

  ldb_buffer_append(&dst->rep, src->rep.data + LDB_HEADER,
                               src->rep.size - LDB_HEADER);
}

static void
memtable_put(ldb_handler_t *handler,
             const ldb_slice_t *key,
             const ldb_slice_t *value) {
  ldb_memtable_t *table = handler->state;
  ldb_seqnum_t seq = handler->number;

  ldb_memtable_add(table, seq, LDB_TYPE_VALUE, key, value);

  handler->number++;
}

static void
memtable_del(ldb_handler_t *handler, const ldb_slice_t *key) {
  static const ldb_slice_t value = {NULL, 0, 0};
  ldb_memtable_t *table = handler->state;
  ldb_seqnum_t seq = handler->number;

  ldb_memtable_add(table, seq, LDB_TYPE_DELETION, key, &value);

  handler->number++;
}

int
ldb_batch_insert_into(const ldb_batch_t *batch, ldb_memtable_t *table) {
  ldb_handler_t handler;

  handler.state = table;
  handler.number = ldb_batch_sequence(batch);
  handler.put = memtable_put;
  handler.del = memtable_del;

  return ldb_batch_iterate(batch, &handler);
}

void
ldb_batch_set_contents(ldb_batch_t *batch, const ldb_slice_t *contents) {
  assert(contents->size >= LDB_HEADER);

  ldb_buffer_copy(&batch->rep, contents);
}

ldb_slice_t
ldb_batch_contents(const ldb_batch_t *batch) {
  return batch->rep;
}

size_t
ldb_batch_size(const ldb_batch_t *batch) {
  return batch->rep.size;
}
