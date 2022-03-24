/*!
 * merger.c - merging iterator for lcdb
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

#include "../util/comparator.h"
#include "../util/internal.h"
#include "../util/slice.h"
#include "../util/status.h"

#include "iterator.h"
#include "iterator_wrapper.h"
#include "merger.h"

/*
 * Constants
 */

enum ldb_direction {
  LDB_FORWARD,
  LDB_REVERSE
};

/*
 * Merging Iterator
 */

typedef struct ldb_mergeiter_s {
  /* We might want to use a heap in case there are lots of children.
     For now we use a simple array since we expect a very small number
     of children in leveldb. */
  const ldb_comparator_t *comparator;
  ldb_wrapiter_t *children;
  int n;
  ldb_wrapiter_t *current;
  enum ldb_direction direction;
} ldb_mergeiter_t;

static void
ldb_mergeiter_init(ldb_mergeiter_t *mi,
                   const ldb_comparator_t *comparator,
                   ldb_iter_t **children,
                   int n) {
  int i;

  mi->comparator = comparator;
  mi->children = ldb_malloc(n * sizeof(ldb_wrapiter_t));
  mi->n = n;
  mi->current = NULL;
  mi->direction = LDB_FORWARD;

  for (i = 0; i < n; i++)
    ldb_wrapiter_init(&mi->children[i], children[i]);
}

static void
ldb_mergeiter_clear(ldb_mergeiter_t *mi) {
  int i;

  for (i = 0; i < mi->n; i++)
    ldb_wrapiter_clear(&mi->children[i]);

  ldb_free(mi->children);
}

static int
ldb_mergeiter_valid(const ldb_mergeiter_t *mi) {
  return (mi->current != NULL);
}

static ldb_slice_t
ldb_mergeiter_key(const ldb_mergeiter_t *mi) {
  assert(ldb_mergeiter_valid(mi));
  return ldb_wrapiter_key(mi->current);
}

static ldb_slice_t
ldb_mergeiter_value(const ldb_mergeiter_t *mi) {
  assert(ldb_mergeiter_valid(mi));
  return ldb_wrapiter_value(mi->current);
}

static int
ldb_mergeiter_status(const ldb_mergeiter_t *mi) {
  int rc = LDB_OK;
  int i;

  for (i = 0; i < mi->n; i++) {
    if ((rc = ldb_wrapiter_status(&mi->children[i])))
      break;
  }

  return rc;
}

static void
ldb_mergeiter_find_smallest(ldb_mergeiter_t *mi) {
  ldb_wrapiter_t *smallest = NULL;
  int i;

  for (i = 0; i < mi->n; i++) {
    ldb_wrapiter_t *child = &mi->children[i];

    if (ldb_wrapiter_valid(child)) {
      if (smallest == NULL) {
        smallest = child;
      } else {
        ldb_slice_t child_key = ldb_wrapiter_key(child);
        ldb_slice_t smallest_key = ldb_wrapiter_key(smallest);

        if (ldb_compare(mi->comparator, &child_key, &smallest_key) < 0)
          smallest = child;
      }
    }
  }

  mi->current = smallest;
}

static void
ldb_mergeiter_find_largest(ldb_mergeiter_t *mi) {
  ldb_wrapiter_t *largest = NULL;
  int i;

  for (i = mi->n - 1; i >= 0; i--) {
    ldb_wrapiter_t *child = &mi->children[i];

    if (ldb_wrapiter_valid(child)) {
      if (largest == NULL) {
        largest = child;
      } else {
        ldb_slice_t child_key = ldb_wrapiter_key(child);
        ldb_slice_t largest_key = ldb_wrapiter_key(largest);

        if (ldb_compare(mi->comparator, &child_key, &largest_key) > 0)
          largest = child;
      }
    }
  }

  mi->current = largest;
}

static void
ldb_mergeiter_first(ldb_mergeiter_t *mi) {
  int i;

  for (i = 0; i < mi->n; i++)
    ldb_wrapiter_first(&mi->children[i]);

  ldb_mergeiter_find_smallest(mi);

  mi->direction = LDB_FORWARD;
}

static void
ldb_mergeiter_last(ldb_mergeiter_t *mi) {
  int i;

  for (i = 0; i < mi->n; i++)
    ldb_wrapiter_last(&mi->children[i]);

  ldb_mergeiter_find_largest(mi);

  mi->direction = LDB_REVERSE;
}

static void
ldb_mergeiter_seek(ldb_mergeiter_t *mi, const ldb_slice_t *target) {
  int i;

  for (i = 0; i < mi->n; i++)
    ldb_wrapiter_seek(&mi->children[i], target);

  ldb_mergeiter_find_smallest(mi);

  mi->direction = LDB_FORWARD;
}

static void
ldb_mergeiter_next(ldb_mergeiter_t *mi) {
  assert(ldb_mergeiter_valid(mi));

  /* Ensure that all children are positioned after key().
     If we are moving in the forward direction, it is already
     true for all of the non-current children since current is
     the smallest child and key() == current->key(). Otherwise,
     we explicitly position the non-current children. */
  if (mi->direction != LDB_FORWARD) {
    int i;

    for (i = 0; i < mi->n; i++) {
      ldb_wrapiter_t *child = &mi->children[i];

      if (child != mi->current) {
        ldb_slice_t mi_key = ldb_mergeiter_key(mi);

        ldb_wrapiter_seek(child, &mi_key);

        if (ldb_wrapiter_valid(child)) {
          ldb_slice_t child_key = ldb_wrapiter_key(child);

          if (ldb_compare(mi->comparator, &mi_key, &child_key) == 0)
            ldb_wrapiter_next(child);
        }
      }
    }

    mi->direction = LDB_FORWARD;
  }

  ldb_wrapiter_next(mi->current);
  ldb_mergeiter_find_smallest(mi);
}

static void
ldb_mergeiter_prev(ldb_mergeiter_t *mi) {
  assert(ldb_mergeiter_valid(mi));

  /* Ensure that all children are positioned before key().
     If we are moving in the reverse direction, it is already
     true for all of the non-current children since current is
     the largest child and key() == current->key(). Otherwise,
     we explicitly position the non-current children. */
  if (mi->direction != LDB_REVERSE) {
    int i;

    for (i = 0; i < mi->n; i++) {
      ldb_wrapiter_t *child = &mi->children[i];

      if (child != mi->current) {
        ldb_slice_t mi_key = ldb_mergeiter_key(mi);

        ldb_wrapiter_seek(child, &mi_key);

        if (ldb_wrapiter_valid(child)) {
          /* Child is at first entry >= key(). Step back one to be < key(). */
          ldb_wrapiter_prev(child);
        } else {
          /* Child has no entries >= key(). Position at last entry. */
          ldb_wrapiter_last(child);
        }
      }
    }

    mi->direction = LDB_REVERSE;
  }

  ldb_wrapiter_prev(mi->current);
  ldb_mergeiter_find_largest(mi);
}

LDB_ITERATOR_FUNCTIONS(ldb_mergeiter);

ldb_iter_t *
ldb_mergeiter_create(const ldb_comparator_t *comparator,
                     ldb_iter_t **children,
                     int n) {
  ldb_mergeiter_t *iter;

  assert(n >= 0);

  if (n == 0)
    return ldb_emptyiter_create(LDB_OK);

  if (n == 1)
    return children[0];

  iter = ldb_malloc(sizeof(ldb_mergeiter_t));

  ldb_mergeiter_init(iter, comparator, children, n);

  return ldb_iter_create(iter, &ldb_mergeiter_table);
}
