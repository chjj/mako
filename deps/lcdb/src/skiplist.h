/*!
 * skiplist.h - skiplist for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on google/leveldb:
 *   Copyright (c) 2011, The LevelDB Authors. All rights reserved.
 *   https://github.com/google/leveldb
 *
 * See LICENSE for more information.
 */

#ifndef LDB_SKIPLIST_H
#define LDB_SKIPLIST_H

#include <stdint.h>

#include "util/atomic.h"
#include "util/random.h"

/*
 * Types
 */

struct ldb_arena_s;
struct ldb_comparator_s;

typedef struct ldb_skipnode_s ldb_skipnode_t;

typedef struct ldb_skiplist_s {
  /* Immutable after construction. */
  const struct ldb_comparator_s *comparator;
  struct ldb_arena_s *arena;
  ldb_skipnode_t *head;

  /* Modified only by insert(). Read racily by readers, but stale
     values are ok. */
  ldb_atomic(int) max_height; /* Height of the entire list. */

  /* Read/written only by insert(). */
  ldb_rand_t rnd;
} ldb_skiplist_t;

typedef struct ldb_skipiter_s {
  const ldb_skiplist_t *list;
  ldb_skipnode_t *node;
} ldb_skipiter_t;

/*
 * SkipList
 */

/* Create a new SkipList object that will use "cmp" for comparing keys,
 * and will allocate memory using "*arena". Objects allocated in the arena
 * must remain allocated for the lifetime of the skiplist object.
 */
void
ldb_skiplist_init(ldb_skiplist_t *list,
                  const struct ldb_comparator_s *cmp,
                  struct ldb_arena_s *arena);

/* Insert key into the list. */
/* REQUIRES: nothing that compares equal to key is currently in the list. */
void
ldb_skiplist_insert(ldb_skiplist_t *list, const uint8_t *key);

/* Returns true iff an entry that compares equal to key is in the list. */
int
ldb_skiplist_contains(const ldb_skiplist_t *list, const uint8_t *key);

/*
 * SkipList::Iterator
 */

/* Initialize an iterator over the specified list. */
/* The returned iterator is not valid. */
void
ldb_skipiter_init(ldb_skipiter_t *iter, const ldb_skiplist_t *list);

/* Returns true iff the iterator is positioned at a valid node. */
int
ldb_skipiter_valid(const ldb_skipiter_t *iter);

/* Returns the key at the current position. */
/* REQUIRES: valid() */
const uint8_t *
ldb_skipiter_key(const ldb_skipiter_t *iter);

/* Advances to the next position. */
/* REQUIRES: valid() */
void
ldb_skipiter_next(ldb_skipiter_t *iter);

/* Advances to the previous position. */
/* REQUIRES: valid() */
void
ldb_skipiter_prev(ldb_skipiter_t *iter);

/* Advance to the first entry with a key >= target */
void
ldb_skipiter_seek(ldb_skipiter_t *iter, const uint8_t *target);

/* Position at the first entry in list. */
/* Final state of iterator is valid() iff list is not empty. */
void
ldb_skipiter_first(ldb_skipiter_t *iter);

/* Position at the last entry in list. */
/* Final state of iterator is valid() iff list is not empty. */
void
ldb_skipiter_last(ldb_skipiter_t *iter);

#endif /* LDB_SKIPLIST_H */
