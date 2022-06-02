/*!
 * db_iter.c - database iterator for lcdb
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

#include "util/buffer.h"
#include "util/comparator.h"
#include "util/internal.h"
#include "util/random.h"
#include "util/slice.h"
#include "util/status.h"

#include "db_impl.h"
#include "db_iter.h"
#include "dbformat.h"

/*
 * Constants
 */

/* Which direction is the iterator currently moving?
 *
 * (1) When moving forward, the internal iterator is positioned at
 *     the exact entry that yields key(iter), value(iter).
 *
 * (2) When moving backwards, the internal iterator is positioned
 *     just before all entries whose user key == key(iter).
 */
enum ldb_direction { LDB_FORWARD, LDB_REVERSE };

/*
 * Types
 */

/* Memtables and sstables that make the DB representation contain
   (userkey,seq,type) => uservalue entries. DBIter
   combines multiple entries for the same userkey found in the DB
   representation into a single entry while accounting for sequence
   numbers, deletion markers, overwrites, etc. */
typedef struct ldb_dbiter_s {
  ldb_t *db;
  const ldb_comparator_t *ucmp;
  ldb_iter_t *iter;
  ldb_seqnum_t sequence;
  int status;
  ldb_buffer_t saved_key;   /* == current key when direction==REVERSE */
  ldb_buffer_t saved_value; /* == current value when direction==REVERSE */
  enum ldb_direction direction;
  int valid;
  ldb_rand_t rnd;
  size_t bytes_until_read_sampling;
} ldb_dbiter_t;

/*
 * Helpers
 */

/* Picks the number of bytes that can be
   read until a compaction is scheduled. */
static size_t
random_compaction_period(ldb_dbiter_t *iter) {
  return ldb_rand_uniform(&iter->rnd, 2 * LDB_READ_BYTES_PERIOD);
}

static LDB_INLINE int
parse_key(ldb_dbiter_t *iter, ldb_pkey_t *ikey) {
  ldb_slice_t k = ldb_iter_key(iter->iter);
  ldb_slice_t v = ldb_iter_value(iter->iter);
  size_t bytes_read = k.size + v.size;

  while (iter->bytes_until_read_sampling < bytes_read) {
    iter->bytes_until_read_sampling += random_compaction_period(iter);
    ldb_record_read_sample(iter->db, &k);
  }

  assert(iter->bytes_until_read_sampling >= bytes_read);

  iter->bytes_until_read_sampling -= bytes_read;

  if (!ldb_pkey_import(ikey, &k)) {
    iter->status = LDB_CORRUPTION; /* "corrupted internal key in DBIter" */
    return 0;
  }

  return 1;
}

static LDB_INLINE void
clear_saved_value(ldb_dbiter_t *iter) {
  if (iter->saved_value.alloc > 1048576) {
    ldb_buffer_clear(&iter->saved_value);
    ldb_buffer_init(&iter->saved_value);
  } else {
    ldb_buffer_reset(&iter->saved_value);
  }
}

static void
find_next_user_entry(ldb_dbiter_t *iter, int skipping, ldb_buffer_t *skip) {
  /* Loop until we hit an acceptable entry to yield. */
  assert(ldb_iter_valid(iter->iter));
  assert(iter->direction == LDB_FORWARD);

  do {
    ldb_pkey_t ikey;

    if (parse_key(iter, &ikey) && ikey.sequence <= iter->sequence) {
      switch (ikey.type) {
        case LDB_TYPE_DELETION:
          /* Arrange to skip all upcoming entries for this key since
             they are hidden by this deletion. */
          ldb_buffer_copy(skip, &ikey.user_key);
          skipping = 1;
          break;
        case LDB_TYPE_VALUE:
          if (skipping && ldb_compare(iter->ucmp, &ikey.user_key, skip) <= 0) {
            /* Entry hidden. */
          } else {
            iter->valid = 1;
            ldb_buffer_reset(&iter->saved_key);
            return;
          }
          break;
      }
    }

    ldb_iter_next(iter->iter);
  } while (ldb_iter_valid(iter->iter));

  ldb_buffer_reset(&iter->saved_key);

  iter->valid = 0;
}

static void
find_prev_user_entry(ldb_dbiter_t *iter) {
  ldb_valtype_t value_type = LDB_TYPE_DELETION;

  assert(iter->direction == LDB_REVERSE);

  if (ldb_iter_valid(iter->iter)) {
    do {
      ldb_pkey_t ikey;

      if (parse_key(iter, &ikey) && ikey.sequence <= iter->sequence) {
        if ((value_type != LDB_TYPE_DELETION) &&
            ldb_compare(iter->ucmp, &ikey.user_key, &iter->saved_key) < 0) {
          /* We encountered a non-deleted value in entries for previous keys. */
          break;
        }

        value_type = ikey.type;

        if (value_type == LDB_TYPE_DELETION) {
          ldb_buffer_reset(&iter->saved_key);
          clear_saved_value(iter);
        } else {
          ldb_slice_t key = ldb_iter_key(iter->iter);
          ldb_slice_t ukey = ldb_extract_user_key(&key);
          ldb_slice_t value = ldb_iter_value(iter->iter);

          if (iter->saved_value.alloc > value.size + 1048576) {
            ldb_buffer_clear(&iter->saved_value);
            ldb_buffer_init(&iter->saved_value);
          }

          ldb_buffer_copy(&iter->saved_key, &ukey);
          ldb_buffer_copy(&iter->saved_value, &value);
        }
      }

      ldb_iter_prev(iter->iter);
    } while (ldb_iter_valid(iter->iter));
  }

  if (value_type == LDB_TYPE_DELETION) {
    /* End. */
    iter->valid = 0;
    ldb_buffer_reset(&iter->saved_key);
    clear_saved_value(iter);
    iter->direction = LDB_FORWARD;
  } else {
    iter->valid = 1;
  }
}

/*
 * DBIter
 */

static void
ldb_dbiter_init(ldb_dbiter_t *iter,
                ldb_t *db,
                const ldb_comparator_t *ucmp,
                ldb_iter_t *internal_iter,
                ldb_seqnum_t sequence,
                uint32_t seed) {
  iter->db = db;
  iter->ucmp = ucmp;
  iter->iter = internal_iter;
  iter->sequence = sequence;
  iter->status = LDB_OK;

  ldb_buffer_init(&iter->saved_key);
  ldb_buffer_init(&iter->saved_value);

  iter->direction = LDB_FORWARD;
  iter->valid = 0;

  ldb_rand_init(&iter->rnd, seed);

  iter->bytes_until_read_sampling = random_compaction_period(iter);
}

static void
ldb_dbiter_clear(ldb_dbiter_t *iter) {
  ldb_iter_destroy(iter->iter);
  ldb_buffer_clear(&iter->saved_key);
  ldb_buffer_clear(&iter->saved_value);
}

static int
ldb_dbiter_valid(const ldb_dbiter_t *iter) {
  return iter->valid;
}

static ldb_slice_t
ldb_dbiter_key(const ldb_dbiter_t *iter) {
  assert(iter->valid);

  if (iter->direction == LDB_FORWARD) {
    ldb_slice_t key = ldb_iter_key(iter->iter);
    return ldb_extract_user_key(&key);
  }

  return iter->saved_key;
}

static ldb_slice_t
ldb_dbiter_value(const ldb_dbiter_t *iter) {
  assert(iter->valid);

  if (iter->direction == LDB_FORWARD)
    return ldb_iter_value(iter->iter);

  return iter->saved_value;
}

static int
ldb_dbiter_status(const ldb_dbiter_t *iter) {
  if (iter->status == LDB_OK)
    return ldb_iter_status(iter->iter);

  return iter->status;
}

static void
ldb_dbiter_next(ldb_dbiter_t *iter) {
  assert(iter->valid);

  if (iter->direction == LDB_REVERSE) { /* Switch directions? */
    iter->direction = LDB_FORWARD;

    /* iter->iter is pointing just before the entries for key(),
       so advance into the range of entries for key() and then
       use the normal skipping code below. */
    if (!ldb_iter_valid(iter->iter))
      ldb_iter_first(iter->iter);
    else
      ldb_iter_next(iter->iter);

    if (!ldb_iter_valid(iter->iter)) {
      iter->valid = 0;
      ldb_buffer_reset(&iter->saved_key);
      return;
    }

    /* iter->saved_key already contains the key to skip past. */
  } else {
    /* Store in iter->saved_key the current key so we skip it below. */
    ldb_slice_t key = ldb_iter_key(iter->iter);
    ldb_slice_t ukey = ldb_extract_user_key(&key);

    ldb_buffer_copy(&iter->saved_key, &ukey);

    /* iter->iter is pointing to current key. We can now
       safely move to the next to avoid checking current key. */
    ldb_iter_next(iter->iter);

    if (!ldb_iter_valid(iter->iter)) {
      iter->valid = 0;
      ldb_buffer_reset(&iter->saved_key);
      return;
    }
  }

  find_next_user_entry(iter, 1, &iter->saved_key);
}

static void
ldb_dbiter_prev(ldb_dbiter_t *iter) {
  assert(iter->valid);

  if (iter->direction == LDB_FORWARD) { /* Switch directions? */
    /* iter->iter is pointing at the current entry. Scan backwards until
       the key changes so we can use the normal reverse scanning code. */
    ldb_slice_t key = ldb_iter_key(iter->iter);
    ldb_slice_t ukey = ldb_extract_user_key(&key);

    assert(ldb_iter_valid(iter->iter)); /* Otherwise iter->valid
                                           would have been false. */

    ldb_buffer_copy(&iter->saved_key, &ukey);

    for (;;) {
      ldb_iter_prev(iter->iter);

      if (!ldb_iter_valid(iter->iter)) {
        iter->valid = 0;
        ldb_buffer_reset(&iter->saved_key);
        clear_saved_value(iter);
        return;
      }

      key = ldb_iter_key(iter->iter);
      ukey = ldb_extract_user_key(&key);

      if (ldb_compare(iter->ucmp, &ukey, &iter->saved_key) < 0)
        break;
    }

    iter->direction = LDB_REVERSE;
  }

  find_prev_user_entry(iter);
}

static void
ldb_dbiter_seek(ldb_dbiter_t *iter, const ldb_slice_t *target) {
  ldb_pkey_t pkey;

  iter->direction = LDB_FORWARD;

  clear_saved_value(iter);

  ldb_buffer_reset(&iter->saved_key);

  ldb_pkey_init(&pkey, target, iter->sequence, LDB_VALTYPE_SEEK);
  ldb_pkey_export(&iter->saved_key, &pkey);

  ldb_iter_seek(iter->iter, &iter->saved_key);

  if (ldb_iter_valid(iter->iter))
    find_next_user_entry(iter, 0, &iter->saved_key);
  else
    iter->valid = 0;
}

static void
ldb_dbiter_first(ldb_dbiter_t *iter) {
  iter->direction = LDB_FORWARD;

  clear_saved_value(iter);

  ldb_iter_first(iter->iter);

  if (ldb_iter_valid(iter->iter))
    find_next_user_entry(iter, 0, &iter->saved_key);
  else
    iter->valid = 0;
}

static void
ldb_dbiter_last(ldb_dbiter_t *iter) {
  iter->direction = LDB_REVERSE;

  clear_saved_value(iter);

  ldb_iter_last(iter->iter);

  find_prev_user_entry(iter);
}

LDB_ITERATOR_FUNCTIONS(ldb_dbiter);

ldb_iter_t *
ldb_dbiter_create(ldb_t *db,
                  const ldb_comparator_t *user_comparator,
                  ldb_iter_t *internal_iter,
                  ldb_seqnum_t sequence,
                  uint32_t seed) {
  ldb_dbiter_t *iter = ldb_malloc(sizeof(ldb_dbiter_t));
  ldb_dbiter_init(iter, db, user_comparator, internal_iter, sequence, seed);
  return ldb_iter_create(iter, &ldb_dbiter_table);
}

int
ldb_iter_compare(const ldb_iter_t *iter, const ldb_slice_t *key) {
  const ldb_dbiter_t *it = iter->ptr;
  ldb_slice_t x = ldb_dbiter_key(it);
  return ldb_compare(it->ucmp, &x, key);
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
