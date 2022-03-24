/*!
 * block.c - block for lcdb
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

#include "../util/buffer.h"
#include "../util/coding.h"
#include "../util/comparator.h"
#include "../util/internal.h"
#include "../util/slice.h"
#include "../util/status.h"

#include "block.h"
#include "format.h"
#include "iterator.h"

/*
 * Block
 */

ldb_block_t *
ldb_block_create(const ldb_blockcontents_t *contents) {
  ldb_block_t *block = ldb_malloc(sizeof(ldb_block_t));
  ldb_block_init(block, contents);
  return block;
}

void
ldb_block_destroy(ldb_block_t *block) {
  ldb_block_clear(block);
  ldb_free(block);
}

static uint32_t
ldb_block_restarts(const ldb_block_t *block) {
  assert(block->size >= 4);
  return ldb_fixed32_decode(block->data + block->size - 4);
}

void
ldb_block_init(ldb_block_t *block, const ldb_blockcontents_t *contents) {
  block->data = contents->data.data;
  block->size = contents->data.size;
  block->restart_offset = 0;
  block->owned = contents->heap_allocated;

  if (block->size < 4) {
    block->size = 0; /* Error marker. */
  } else {
    size_t max_restarts_allowed = (block->size - 4) / 4;

    if (ldb_block_restarts(block) > max_restarts_allowed) {
      /* The size is too small for ldb_block_restarts(). */
      block->size = 0;
    } else {
      block->restart_offset = block->size - (1 + ldb_block_restarts(block)) * 4;
    }
  }
}

void
ldb_block_clear(ldb_block_t *block) {
  if (block->owned)
    ldb_free((void *)block->data);
}

/* Helper routine: decode the next block entry starting at "xp",
 * storing the number of shared key bytes, non_shared key bytes,
 * and the length of the value in "*shared", "*non_shared", and
 * "*value_length", respectively. Will not dereference past "limit".
 *
 * If any errors are detected, returns NULL. Otherwise, returns a
 * pointer to the key delta (just past the three decoded values).
 */
static const uint8_t *
ldb_decode_entry(uint32_t *shared,
                 uint32_t *non_shared,
                 uint32_t *value_length,
                 const uint8_t *xp,
                 const uint8_t *limit) {
  size_t xn;

  if (limit < xp)
    return NULL;

  xn = limit - xp;

  if (xn < 3)
    return NULL;

  *shared = xp[0];
  *non_shared = xp[1];
  *value_length = xp[2];

  if ((*shared | *non_shared | *value_length) < 128) {
    /* Fast path: all three values are encoded in one byte each. */
    xp += 3;
    xn -= 3;
  } else {
    if (!ldb_varint32_read(shared, &xp, &xn))
      return NULL;

    if (!ldb_varint32_read(non_shared, &xp, &xn))
      return NULL;

    if (!ldb_varint32_read(value_length, &xp, &xn))
      return NULL;
  }

  if (xn < (*non_shared + *value_length))
    return NULL;

  return xp;
}

/*
 * Block Iterator
 */

typedef struct ldb_blockiter_s {
  const ldb_comparator_t *comparator;
  const uint8_t *data;    /* Underlying block contents. */
  uint32_t restarts;      /* Offset of restart array (list of fixed32). */
  uint32_t num_restarts;  /* Number of uint32_t entries in restart array. */

  /* current is offset in data of current entry. >= restarts if !valid. */
  uint32_t current;
  uint32_t restart_index; /* Index of restart block in which current falls. */
  ldb_buffer_t key;
  ldb_slice_t value;
  int status;
} ldb_blockiter_t;

static int
ldb_blockiter_compare(const ldb_blockiter_t *iter,
                      const ldb_slice_t *x,
                      const ldb_slice_t *y) {
  return ldb_compare(iter->comparator, x, y);
}

/* Return the offset in iter->data just past the end of the current entry. */
static uint32_t
ldb_blockiter_next_entry_offset(const ldb_blockiter_t *iter) {
  return (iter->value.data + iter->value.size) - iter->data;
}

static uint32_t
ldb_blockiter_restart_point(const ldb_blockiter_t *iter, uint32_t index) {
  assert(index < iter->num_restarts);
  return ldb_fixed32_decode(iter->data + iter->restarts + index * 4);
}

static void
ldb_blockiter_seek_restart(ldb_blockiter_t *iter, uint32_t index) {
  uint32_t offset;

  ldb_buffer_reset(&iter->key);

  iter->restart_index = index;

  /* iter->current will be fixed by parse_next_key() */

  /* parse_next_key() starts at the end of iter->value,
     so set iter->value accordingly */
  offset = ldb_blockiter_restart_point(iter, index);

  ldb_slice_set(&iter->value, iter->data + offset, 0);
}

static void
ldb_blockiter_init(ldb_blockiter_t *iter,
                   const ldb_comparator_t *comparator,
                   const uint8_t *data,
                   uint32_t restarts,
                   uint32_t num_restarts) {
  assert(num_restarts > 0);

  iter->comparator = comparator;
  iter->data = data;
  iter->restarts = restarts;
  iter->num_restarts = num_restarts;
  iter->current = iter->restarts;
  iter->restart_index = iter->num_restarts;

  ldb_buffer_init(&iter->key);
  ldb_slice_init(&iter->value);

  iter->status = LDB_OK;
}

static void
ldb_blockiter_corruption(ldb_blockiter_t *iter) {
  iter->current = iter->restarts;
  iter->restart_index = iter->num_restarts;
  iter->status = LDB_CORRUPTION; /* "bad entry in block" */

  ldb_buffer_reset(&iter->key);
  ldb_slice_reset(&iter->value);
}

static void
ldb_blockiter_clear(ldb_blockiter_t *iter) {
  ldb_buffer_clear(&iter->key);
}

static int
ldb_blockiter_valid(const ldb_blockiter_t *iter) {
  return iter->current < iter->restarts;
}

static int
ldb_blockiter_status(const ldb_blockiter_t *iter) {
  return iter->status;
}

static ldb_slice_t
ldb_blockiter_key(const ldb_blockiter_t *iter) {
  assert(ldb_blockiter_valid(iter));
  return iter->key;
}

static ldb_slice_t
ldb_blockiter_value(const ldb_blockiter_t *iter) {
  assert(ldb_blockiter_valid(iter));
  return iter->value;
}

static int
ldb_blockiter_parse_next_key(ldb_blockiter_t *iter);

static void
ldb_blockiter_next(ldb_blockiter_t *iter) {
  assert(ldb_blockiter_valid(iter));

  ldb_blockiter_parse_next_key(iter);
}

static void
ldb_blockiter_prev(ldb_blockiter_t *iter) {
  uint32_t original = iter->current;

  assert(ldb_blockiter_valid(iter));

  /* Scan backwards to a restart point before iter->current. */
  while (ldb_blockiter_restart_point(iter, iter->restart_index) >= original) {
    if (iter->restart_index == 0) {
      /* No more entries. */
      iter->current = iter->restarts;
      iter->restart_index = iter->num_restarts;
      return;
    }

    iter->restart_index--;
  }

  ldb_blockiter_seek_restart(iter, iter->restart_index);

  do {
    /* Loop until end of current entry hits the start of original entry. */
  } while (ldb_blockiter_parse_next_key(iter)
        && ldb_blockiter_next_entry_offset(iter) < original);
}

static void
ldb_blockiter_seek(ldb_blockiter_t *iter, const ldb_slice_t *target) {
  /* Binary search in restart array to find the
     last restart point with a key < target. */
  uint32_t left = 0;
  uint32_t right = iter->num_restarts - 1;
  int current_key_compare = 0;
  int skip_seek;

  if (ldb_blockiter_valid(iter)) {
    /* If we're already scanning, use the current position as a starting
       point. This is beneficial if the key we're seeking to is ahead of the
       current position. */
    current_key_compare = ldb_blockiter_compare(iter, &iter->key, target);

    if (current_key_compare < 0) {
      /* iter->key is smaller than target. */
      left = iter->restart_index;
    } else if (current_key_compare > 0) {
      right = iter->restart_index;
    } else {
      /* We're seeking to the key we're already at. */
      return;
    }
  }

  while (left < right) {
    uint32_t mid = (left + right + 1) / 2;
    uint32_t region_offset = ldb_blockiter_restart_point(iter, mid);
    uint32_t shared, non_shared, value_length;
    const uint8_t *key_ptr = ldb_decode_entry(&shared,
                                              &non_shared,
                                              &value_length,
                                              iter->data + region_offset,
                                              iter->data + iter->restarts);
    ldb_slice_t mid_key;

    if (key_ptr == NULL || (shared != 0)) {
      ldb_blockiter_corruption(iter);
      return;
    }

    ldb_slice_set(&mid_key, key_ptr, non_shared);

    if (ldb_blockiter_compare(iter, &mid_key, target) < 0) {
      /* Key at "mid" is smaller than "target".  Therefore all
         blocks before "mid" are uninteresting. */
      left = mid;
    } else {
      /* Key at "mid" is >= "target".  Therefore all blocks at or
         after "mid" are uninteresting. */
      right = mid - 1;
    }
  }

  /* We might be able to use our current position within the restart block.
     This is true if we determined the key we desire is in the current block
     and is after than the current key. */
  assert(current_key_compare == 0 || ldb_blockiter_valid(iter));

  skip_seek = (left == iter->restart_index && current_key_compare < 0);

  if (!skip_seek)
    ldb_blockiter_seek_restart(iter, left);

  /* Linear search (within restart block) for first key >= target. */
  for (;;) {
    if (!ldb_blockiter_parse_next_key(iter))
      return;

    if (ldb_blockiter_compare(iter, &iter->key, target) >= 0)
      return;
  }
}

static void
ldb_blockiter_first(ldb_blockiter_t *iter) {
  ldb_blockiter_seek_restart(iter, 0);
  ldb_blockiter_parse_next_key(iter);
}

static void
ldb_blockiter_last(ldb_blockiter_t *iter) {
  ldb_blockiter_seek_restart(iter, iter->num_restarts - 1);

  while (ldb_blockiter_parse_next_key(iter)
      && ldb_blockiter_next_entry_offset(iter) < iter->restarts) {
    /* Keep skipping. */
  }
}

static int
ldb_blockiter_parse_next_key(ldb_blockiter_t *iter) {
  uint32_t shared, non_shared, value_length;
  const uint8_t *p, *limit;

  iter->current = ldb_blockiter_next_entry_offset(iter);

  p = iter->data + iter->current;
  limit = iter->data + iter->restarts; /* Restarts come right after data. */

  if (p >= limit) {
    /* No more entries to return. Mark as invalid. */
    iter->current = iter->restarts;
    iter->restart_index = iter->num_restarts;
    return 0;
  }

  /* Decode next entry. */
  p = ldb_decode_entry(&shared, &non_shared, &value_length, p, limit);

  if (p == NULL || iter->key.size < shared) {
    ldb_blockiter_corruption(iter);
    return 0;
  }

  ldb_buffer_resize(&iter->key, shared);
  ldb_buffer_append(&iter->key, p, non_shared);

  ldb_slice_set(&iter->value, p + non_shared, value_length);

  while (iter->restart_index + 1 < iter->num_restarts
      && ldb_blockiter_restart_point(iter, iter->restart_index + 1) < iter->current) {
    ++iter->restart_index;
  }

  return 1;
}

LDB_ITERATOR_FUNCTIONS(ldb_blockiter);

ldb_iter_t *
ldb_blockiter_create(const ldb_block_t *block,
                     const ldb_comparator_t *comparator) {
  ldb_blockiter_t *iter;
  uint32_t num_restarts;

  if (block->size < 4)
    return ldb_emptyiter_create(LDB_CORRUPTION); /* "bad block contents" */

  num_restarts = ldb_block_restarts(block);

  if (num_restarts == 0)
    return ldb_emptyiter_create(LDB_OK);

  iter = ldb_malloc(sizeof(ldb_blockiter_t));

  ldb_blockiter_init(iter,
                     comparator,
                     block->data,
                     block->restart_offset,
                     num_restarts);

  return ldb_iter_create(iter, &ldb_blockiter_table);
}
