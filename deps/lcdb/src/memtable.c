/*!
 * memtable.c - memtable for lcdb
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

#include "util/arena.h"
#include "util/buffer.h"
#include "util/coding.h"
#include "util/comparator.h"
#include "util/internal.h"
#include "util/slice.h"
#include "util/status.h"

#include "dbformat.h"
#include "memtable.h"
#include "skiplist.h"

/*
 * MemTable
 */

struct ldb_memtable_s {
  ldb_comparator_t comparator;
  int refs;
  ldb_arena_t arena;
  ldb_skiplist_t table;
};

static void
ldb_memtable_init(ldb_memtable_t *mt, const ldb_comparator_t *comparator) {
  assert(comparator->user_comparator != NULL);

  mt->comparator = *comparator;
  mt->refs = 0;

  ldb_arena_init(&mt->arena);

  ldb_skiplist_init(&mt->table, &mt->comparator, &mt->arena);
}

static void
ldb_memtable_clear(ldb_memtable_t *mt) {
  assert(mt->refs == 0);

  ldb_arena_clear(&mt->arena);
}

ldb_memtable_t *
ldb_memtable_create(const ldb_comparator_t *comparator) {
  ldb_memtable_t *mt = ldb_malloc(sizeof(ldb_memtable_t));
  ldb_memtable_init(mt, comparator);
  return mt;
}

void
ldb_memtable_destroy(ldb_memtable_t *mt) {
  ldb_memtable_clear(mt);
  ldb_free(mt);
}

void
ldb_memtable_ref(ldb_memtable_t *mt) {
  ++mt->refs;
}

void
ldb_memtable_unref(ldb_memtable_t *mt) {
  --mt->refs;

  assert(mt->refs >= 0);

  if (mt->refs <= 0)
    ldb_memtable_destroy(mt);
}

size_t
ldb_memtable_usage(const ldb_memtable_t *mt) {
  return ldb_arena_usage(&mt->arena);
}

void
ldb_memtable_add(ldb_memtable_t *mt,
                 ldb_seqnum_t sequence,
                 ldb_valtype_t type,
                 const ldb_slice_t *key,
                 const ldb_slice_t *value) {
  /* Format of an entry is concatenation of:
   *
   *  key_size     : varint32 of internal_key.size()
   *  key bytes    : char[internal_key.size()]
   *  tag          : uint64((sequence << 8) | type)
   *  value_size   : varint32 of value.size()
   *  value bytes  : char[value.size()]
   */
  size_t val_size = value->size;
  size_t ikey_size = key->size + 8;
  uint8_t *tp, *zp;
  size_t zn = 0;

  zn += ldb_varint32_size(ikey_size) + ikey_size;
  zn += ldb_varint32_size(val_size) + val_size;

  tp = ldb_arena_alloc(&mt->arena, zn);
  zp = tp;

  zp = ldb_varint32_write(zp, ikey_size);
  zp = ldb_raw_write(zp, key->data, key->size);
  zp = ldb_fixed64_write(zp, (sequence << 8) | type);

  zp = ldb_varint32_write(zp, val_size);
  zp = ldb_raw_write(zp, value->data, value->size);

  assert(zp == tp + zn);

  ldb_skiplist_insert(&mt->table, tp);
}

int
ldb_memtable_get(ldb_memtable_t *mt,
                 const ldb_lkey_t *key,
                 ldb_buffer_t *value,
                 int *status) {
  ldb_slice_t mkey = ldb_lkey_memtable_key(key);
  ldb_skipiter_t iter;

  ldb_skipiter_init(&iter, &mt->table);
  ldb_skipiter_seek(&iter, mkey.data);

  if (ldb_skipiter_valid(&iter)) {
    /* Entry format is:
     *
     *    klength  varint32
     *    userkey  char[klength]
     *    tag      uint64
     *    vlength  varint32
     *    value    char[vlength]
     *
     * Check that it belongs to same user key. We do not check the
     * sequence number since the seek() call above should have skipped
     * all entries with overly large sequence numbers.
     */
    const ldb_comparator_t *cmp = mt->comparator.user_comparator;
    ldb_slice_t okey = ldb_slice_decode(ldb_skipiter_key(&iter));
    ldb_slice_t ukey = ldb_lkey_user_key(key);

    assert(okey.size >= 8);

    okey.size -= 8;

    if (ldb_compare(cmp, &okey, &ukey) == 0) {
      /* Correct user key. */
      uint64_t tag = ldb_fixed64_decode(okey.data + okey.size);

      switch ((ldb_valtype_t)(tag & 0xff)) {
        case LDB_TYPE_VALUE: {
          if (value != NULL) {
            ldb_slice_t val = ldb_slice_decode(okey.data + okey.size + 8);
            ldb_buffer_copy(value, &val);
          }
          return 1;
        }

        case LDB_TYPE_DELETION: {
          *status = LDB_NOTFOUND;
          return 1;
        }
      }
    }
  }

  return 0;
}

/*
 * MemTable Iterator
 */

typedef struct ldb_memiter_s {
  ldb_skipiter_t iter;
  ldb_buffer_t tmp;
} ldb_memiter_t;

static void
ldb_memiter_init(ldb_memiter_t *iter, const ldb_skiplist_t *table) {
  ldb_skipiter_init(&iter->iter, table);
  ldb_buffer_init(&iter->tmp);
}

static void
ldb_memiter_clear(ldb_memiter_t *iter) {
  ldb_buffer_clear(&iter->tmp);
}

static int
ldb_memiter_valid(const ldb_memiter_t *iter) {
  return ldb_skipiter_valid(&iter->iter);
}

static void
ldb_memiter_seek(ldb_memiter_t *iter, const ldb_slice_t *key) {
  ldb_buffer_t *tmp = &iter->tmp;

  ldb_buffer_reset(tmp);
  ldb_slice_export(tmp, key);

  ldb_skipiter_seek(&iter->iter, tmp->data);
}

static void
ldb_memiter_seek_first(ldb_memiter_t *iter) {
  ldb_skipiter_seek_first(&iter->iter);
}

static void
ldb_memiter_seek_last(ldb_memiter_t *iter) {
  ldb_skipiter_seek_last(&iter->iter);
}

static void
ldb_memiter_next(ldb_memiter_t *iter) {
  ldb_skipiter_next(&iter->iter);
}

static void
ldb_memiter_prev(ldb_memiter_t *iter) {
  ldb_skipiter_prev(&iter->iter);
}

static ldb_slice_t
ldb_memiter_key(const ldb_memiter_t *iter) {
  return ldb_slice_decode(ldb_skipiter_key(&iter->iter));
}

static ldb_slice_t
ldb_memiter_value(const ldb_memiter_t *iter) {
  ldb_slice_t key = ldb_memiter_key(iter);
  return ldb_slice_decode(key.data + key.size);
}

static int
ldb_memiter_status(const ldb_memiter_t *iter) {
  (void)iter;
  return LDB_OK;
}

LDB_ITERATOR_FUNCTIONS(ldb_memiter);

ldb_iter_t *
ldb_memiter_create(const ldb_memtable_t *mt) {
  ldb_memiter_t *iter = ldb_malloc(sizeof(ldb_memiter_t));

  ldb_memiter_init(iter, &mt->table);

  return ldb_iter_create(iter, &ldb_memiter_table);
}
