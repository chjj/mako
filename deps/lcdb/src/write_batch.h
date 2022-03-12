/*!
 * write_batch.h - write batch for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on google/leveldb:
 *   Copyright (c) 2011, The LevelDB Authors. All rights reserved.
 *   https://github.com/google/leveldb
 *
 * See LICENSE for more information.
 */

#ifndef LDB_WRITE_BATCH_H
#define LDB_WRITE_BATCH_H

#include <stddef.h>
#include <stdint.h>

#include "util/extern.h"
#include "util/types.h"

/* Batch holds a collection of updates to apply atomically to a DB.
 *
 * The updates are applied in the order in which they are added
 * to the batch. For example, the value of "key" will be "v3"
 * after the following batch is written:
 *
 *    batch.Put("key", "v1");
 *    batch.Delete("key");
 *    batch.Put("key", "v2");
 *    batch.Put("key", "v3");
 *
 * Multiple threads can invoke const methods on a batch without
 * external synchronization, but if any of the threads may call a
 * non-const method, all threads accessing the same batch must use
 * external synchronization.
 */

/*
 * Types
 */

struct ldb_memtable_s;

typedef uint64_t ldb__seqnum_t;

typedef struct ldb_handler_s {
  void *state;
  uint64_t number;

  void (*put)(struct ldb_handler_s *handler,
              const ldb_slice_t *key,
              const ldb_slice_t *value);

  void (*del)(struct ldb_handler_s *handler,
              const ldb_slice_t *key);
} ldb_handler_t;

typedef struct ldb_batch_s {
  ldb_buffer_t rep; /* See comment in write_batch.c for the format of rep. */
} ldb_batch_t;

/*
 * Batch
 */

LDB_EXTERN ldb_batch_t *
ldb_batch_create(void);

LDB_EXTERN void
ldb_batch_destroy(ldb_batch_t *batch);

LDB_EXTERN void
ldb_batch_init(ldb_batch_t *batch);

LDB_EXTERN void
ldb_batch_clear(ldb_batch_t *batch);

/* Clear all updates buffered in this batch. */
LDB_EXTERN void
ldb_batch_reset(ldb_batch_t *batch);

/* The size of the database changes caused by this batch.
 *
 * This number is tied to implementation details, and may change across
 * releases. It is intended for usage metrics.
 */
LDB_EXTERN size_t
ldb_batch_approximate_size(const ldb_batch_t *batch);

/* Support for iterating over the contents of a batch. */
LDB_EXTERN int
ldb_batch_iterate(const ldb_batch_t *batch, ldb_handler_t *handler);

/* Return the number of entries in the batch. */
int
ldb_batch_count(const ldb_batch_t *batch);

/* Set the count for the number of entries in the batch. */
void
ldb_batch_set_count(ldb_batch_t *batch, int count);

/* Return the sequence number for the start of this batch. */
ldb__seqnum_t
ldb_batch_sequence(const ldb_batch_t *batch);

/* Store the specified number as the sequence number for the start of
   this batch. */
void
ldb_batch_set_sequence(ldb_batch_t *batch, ldb__seqnum_t seq);

/* Store the mapping "key->value" in the database. */
LDB_EXTERN void
ldb_batch_put(ldb_batch_t *batch,
              const ldb_slice_t *key,
              const ldb_slice_t *value);

/* If the database contains a mapping for "key", erase it. Else do nothing. */
LDB_EXTERN void
ldb_batch_del(ldb_batch_t *batch, const ldb_slice_t *key);

/* Copies the operations in "src" to this batch.
 *
 * This runs in O(source size) time. However, the constant factor is better
 * than calling iterate() over the source batch with a Handler that replicates
 * the operations into this batch.
 */
LDB_EXTERN void
ldb_batch_append(ldb_batch_t *dst, const ldb_batch_t *src);

int
ldb_batch_insert_into(const ldb_batch_t *batch, struct ldb_memtable_s *table);

void
ldb_batch_set_contents(ldb_batch_t *batch, const ldb_slice_t *contents);

ldb_slice_t
ldb_batch_contents(const ldb_batch_t *batch);

size_t
ldb_batch_size(const ldb_batch_t *batch);

#endif /* LDB_WRITE_BATCH_H */
