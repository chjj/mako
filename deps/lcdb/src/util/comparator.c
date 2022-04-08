/*!
 * comparator.c - comparator for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on google/leveldb:
 *   Copyright (c) 2011, The LevelDB Authors. All rights reserved.
 *   https://github.com/google/leveldb
 *
 * See LICENSE for more information.
 */

#include <stddef.h>
#include <stdint.h>

#include "buffer.h"
#include "comparator.h"
#include "internal.h"
#include "slice.h"

/*
 * Bytewise Comparator
 */

static int
slice_compare(const ldb_comparator_t *comparator,
              const ldb_slice_t *x,
              const ldb_slice_t *y) {
  size_t n = LDB_MIN(x->size, y->size);
  int r = n ? memcmp(x->data, y->data, n) : 0;

  (void)comparator;

  if (r == 0) {
    if (x->size < y->size)
      r = -1;
    else if (x->size > y->size)
      r = +1;
  }

  return r;
}

static void
shortest_separator(const ldb_comparator_t *comparator,
                   ldb_buffer_t *start,
                   const ldb_slice_t *limit) {
  /* Find length of common prefix. */
  size_t min_length = LDB_MIN(start->size, limit->size);
  size_t diff_index = 0;

  (void)comparator;

  while (diff_index < min_length &&
         start->data[diff_index] == limit->data[diff_index]) {
    diff_index++;
  }

  if (diff_index >= min_length) {
    /* Do not shorten if one string is a prefix of the other. */
  } else {
    uint8_t diff_byte = start->data[diff_index];

    if (diff_byte < 0xff && diff_byte + 1 < limit->data[diff_index]) {
      start->data[diff_index]++;

      ldb_buffer_resize(start, diff_index + 1);
    }
  }
}

static void
short_successor(const ldb_comparator_t *comparator, ldb_buffer_t *key) {
  /* Find first character that can be incremented. */
  size_t i;

  (void)comparator;

  for (i = 0; i < key->size; i++) {
    if (key->data[i] != 0xff) {
      key->data[i] += 1;
      ldb_buffer_resize(key, i + 1);
      return;
    }
  }

  /* key is a run of 0xffs. Leave it alone. */
}

static const ldb_comparator_t bytewise_comparator = {
  /* .name = */ "leveldb.BytewiseComparator",
  /* .compare = */ slice_compare,
  /* .shortest_separator = */ shortest_separator,
  /* .short_successor = */ short_successor,
  /* .user_comparator = */ NULL,
  /* .state = */ NULL
};

/*
 * Globals
 */

const ldb_comparator_t *ldb_bytewise_comparator = &bytewise_comparator;
