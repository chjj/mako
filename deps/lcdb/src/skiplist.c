/*!
 * skiplist.c - skiplist for lcdb
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

#include "util/arena.h"
#include "util/atomic.h"
#include "util/coding.h" /* don't need */
#include "util/comparator.h"
#include "util/internal.h"
#include "util/random.h"
#include "util/slice.h"

#include "skiplist.h"

/* Thread safety
 * -------------
 *
 * Writes require external synchronization, most likely a mutex.
 * Reads require a guarantee that the SkipList will not be destroyed
 * while the read is in progress. Apart from that, reads progress
 * without any internal locking or synchronization.
 *
 * Invariants:
 *
 * (1) Allocated nodes are never deleted until the SkipList is
 * destroyed. This is trivially guaranteed by the code since we
 * never delete any skip list nodes.
 *
 * (2) The contents of a Node except for the next/prev pointers are
 * immutable after the Node has been linked into the SkipList.
 * Only insert() modifies the list, and it is careful to initialize
 * a node and use release-stores to publish the nodes in one or
 * more lists.
 *
 * ... prev vs. next pointer ordering ...
 */

/*
 * Constants
 */

#define LDB_MAX_HEIGHT 12

/*
 * SkipList::Node
 */

struct ldb_skipnode_s {
  const uint8_t *key;
  /* Array of length equal to the node height.
     next[0] is lowest level link. */
  ldb_atomic_ptr(struct ldb_skipnode_s) next[1];
};

static void
ldb_skipnode_init(ldb_skipnode_t *node, const uint8_t *key) {
  node->key = key;
}

static ldb_skipnode_t *
ldb_skipnode_next(ldb_skipnode_t *node, int n) {
  assert(n >= 0);
  /* Use an 'acquire load' so that we observe a fully initialized
     version of the returned Node. */
  return ldb_atomic_load_ptr(&node->next[n], ldb_order_acquire);
}

static void
ldb_skipnode_setnext(ldb_skipnode_t *node, int n, ldb_skipnode_t *x) {
  assert(n >= 0);
  /* Use a 'release store' so that anybody who reads through this
     pointer observes a fully initialized version of the inserted node. */
  ldb_atomic_store_ptr(&node->next[n], x, ldb_order_release);
}

/* No-barrier variants that can be safely used in a few locations. */
static ldb_skipnode_t *
ldb_skipnode_next_nb(ldb_skipnode_t *node, int n) {
  assert(n >= 0);
  return ldb_atomic_load_ptr(&node->next[n], ldb_order_relaxed);
}

static void
ldb_skipnode_setnext_nb(ldb_skipnode_t *node, int n, ldb_skipnode_t *x) {
  assert(n >= 0);
  ldb_atomic_store_ptr(&node->next[n], x, ldb_order_relaxed);
}

static ldb_skipnode_t *
ldb_skipnode_create(ldb_skiplist_t *list, const uint8_t *key, int height) {
  size_t size = (sizeof(ldb_skipnode_t)
               + sizeof(ldb_atomic_ptr(ldb_skipnode_t)) * (height - 1));

  ldb_skipnode_t *node = ldb_arena_alloc_aligned(list->arena, size);

  memset(node, 0, size);

  ldb_skipnode_init(node, key);

  return node;
}

/*
 * SkipList
 */

void
ldb_skiplist_init(ldb_skiplist_t *list,
                  const ldb_comparator_t *cmp,
                  ldb_arena_t *arena) {
  int i;

  list->comparator = cmp;
  list->arena = arena;
  list->head = ldb_skipnode_create(list, NULL, LDB_MAX_HEIGHT);
  list->max_height = 1;

  ldb_rand_init(&list->rnd, 0xdeadbeef);

  for (i = 0; i < LDB_MAX_HEIGHT; i++)
    ldb_skipnode_setnext(list->head, i, NULL);
}

static int
ldb_skiplist_maxheight(const ldb_skiplist_t *list) {
  return ldb_atomic_load(&list->max_height, ldb_order_relaxed);
}

/* MemTable::KeyComparator::operator() */
static int
ldb_skiplist_compare(const ldb_skiplist_t *list,
                     const uint8_t *xp,
                     const uint8_t *yp) {
  /* Internal keys are encoded as length-prefixed strings. */
  ldb_slice_t x = ldb_slice_decode(xp);
  ldb_slice_t y = ldb_slice_decode(yp);

  return ldb_compare(list->comparator, &x, &y);
}

static int
ldb_skiplist_equal(const ldb_skiplist_t *list,
                   const uint8_t *xp,
                   const uint8_t *yp) {
  return ldb_skiplist_compare(list, xp, yp) == 0;
}

static int
ldb_skiplist_randheight(ldb_skiplist_t *list) {
  /* Increase height with probability 1 in 4. */
  int height = 1;

  while (height < LDB_MAX_HEIGHT && ldb_rand_one_in(&list->rnd, 4))
    height++;

  assert(height > 0);
  assert(height <= LDB_MAX_HEIGHT);

  return height;
}

/* Return true if key is greater than the data stored in "n". */
static int
ldb_skiplist_key_after_node(const ldb_skiplist_t *list,
                            const uint8_t *key,
                            ldb_skipnode_t *node) {
  /* A null node is considered infinite. */
  return (node != NULL) && (ldb_skiplist_compare(list, node->key, key) < 0);
}

/* Return the earliest node that comes at or after key.
 * Return nullptr if there is no such node.
 *
 * If prev is non-null, fills prev[level] with pointer to previous
 * node at "level" for every level in [0..max_height_-1].
 */
static ldb_skipnode_t *
ldb_skiplist_find_gte(const ldb_skiplist_t *list,
                      const uint8_t *key,
                      ldb_skipnode_t **prev) {
  int level = ldb_skiplist_maxheight(list) - 1;
  ldb_skipnode_t *x = list->head;

  for (;;) {
    ldb_skipnode_t *next = ldb_skipnode_next(x, level);

    if (ldb_skiplist_key_after_node(list, key, next)) {
      /* Keep searching in this list. */
      x = next;
    } else {
      if (prev != NULL)
        prev[level] = x;

      if (level == 0)
        return next;

      /* Switch to next list. */
      level--;
    }
  }
}

/* Return the latest node with a key < key. */
/* Return head if there is no such node. */
static ldb_skipnode_t *
ldb_skiplist_find_lt(const ldb_skiplist_t *list, const uint8_t *key) {
  int level = ldb_skiplist_maxheight(list) - 1;
  ldb_skipnode_t *x = list->head;
  ldb_skipnode_t *next;

  for (;;) {
    assert(x == list->head || ldb_skiplist_compare(list, x->key, key) < 0);

    next = ldb_skipnode_next(x, level);

    if (next == NULL || ldb_skiplist_compare(list, next->key, key) >= 0) {
      if (level == 0)
        return x;

      /* Switch to next list. */
      level--;
    } else {
      x = next;
    }
  }
}

/* Return the last node in the list. */
/* Return head if list is empty. */
static ldb_skipnode_t *
ldb_skiplist_find_last(const ldb_skiplist_t *list) {
  int level = ldb_skiplist_maxheight(list) - 1;
  ldb_skipnode_t *x = list->head;

  for (;;) {
    ldb_skipnode_t *next = ldb_skipnode_next(x, level);

    if (next == NULL) {
      if (level == 0)
        return x;

      /* Switch to next list. */
      level--;
    } else {
      x = next;
    }
  }
}

void
ldb_skiplist_insert(ldb_skiplist_t *list, const uint8_t *key) {
  ldb_skipnode_t *prev[LDB_MAX_HEIGHT];
  ldb_skipnode_t *x = ldb_skiplist_find_gte(list, key, prev);
  int i, height;

  /* Our data structure does not allow duplicate insertion. */
  assert(x == NULL || !ldb_skiplist_equal(list, key, x->key));

  height = ldb_skiplist_randheight(list);

  if (height > ldb_skiplist_maxheight(list)) {
    for (i = ldb_skiplist_maxheight(list); i < height; i++)
      prev[i] = list->head;

    /* It is ok to mutate max_height without any synchronization
       with concurrent readers. A concurrent reader that observes
       the new value of max_height will see either the old value of
       new level pointers from head (NULL), or a new value set in
       the loop below. In the former case the reader will
       immediately drop to the next level since NULL sorts after all
       keys. In the latter case the reader will use the new node. */
    ldb_atomic_store(&list->max_height, height, ldb_order_relaxed);
  }

  x = ldb_skipnode_create(list, key, height);

  for (i = 0; i < height; i++) {
    /* ldb_skipnode_setnext_nb() suffices since we will add a
       barrier when we publish a pointer to "x" in prev[i]. */
    ldb_skipnode_setnext_nb(x, i, ldb_skipnode_next_nb(prev[i], i));
    ldb_skipnode_setnext(prev[i], i, x);
  }
}

int
ldb_skiplist_contains(const ldb_skiplist_t *list, const uint8_t *key) {
  ldb_skipnode_t *x = ldb_skiplist_find_gte(list, key, NULL);

  if (x != NULL && ldb_skiplist_equal(list, key, x->key))
    return 1;

  return 0;
}

/*
 * SkipList::Iterator
 */

void
ldb_skipiter_init(ldb_skipiter_t *iter, const ldb_skiplist_t *list) {
  iter->list = list;
  iter->node = NULL;
}

int
ldb_skipiter_valid(const ldb_skipiter_t *iter) {
  return iter->node != NULL;
}

const uint8_t *
ldb_skipiter_key(const ldb_skipiter_t *iter) {
  assert(ldb_skipiter_valid(iter));
  return iter->node->key;
}

void
ldb_skipiter_next(ldb_skipiter_t *iter) {
  assert(ldb_skipiter_valid(iter));

  iter->node = ldb_skipnode_next(iter->node, 0);
}

void
ldb_skipiter_prev(ldb_skipiter_t *iter) {
  /* Instead of using explicit "prev" links, we just
     search for the last node that falls before key. */
  assert(ldb_skipiter_valid(iter));

  iter->node = ldb_skiplist_find_lt(iter->list, iter->node->key);

  if (iter->node == iter->list->head)
    iter->node = NULL;
}

void
ldb_skipiter_seek(ldb_skipiter_t *iter, const uint8_t *target) {
  iter->node = ldb_skiplist_find_gte(iter->list, target, NULL);
}

void
ldb_skipiter_seek_first(ldb_skipiter_t *iter) {
  iter->node = ldb_skipnode_next(iter->list->head, 0);
}

void
ldb_skipiter_seek_last(ldb_skipiter_t *iter) {
  iter->node = ldb_skiplist_find_last(iter->list);

  if (iter->node == iter->list->head)
    iter->node = NULL;
}
