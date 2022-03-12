/*!
 * snapshot.h - snapshots for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on google/leveldb:
 *   Copyright (c) 2011, The LevelDB Authors. All rights reserved.
 *   https://github.com/google/leveldb
 *
 * See LICENSE for more information.
 */

#ifndef LDB_SNAPSHOT_H
#define LDB_SNAPSHOT_H

#include <assert.h>
#include <stddef.h>

#include "util/internal.h"

#include "dbformat.h"

/*
 * Types
 */

struct ldb_snaplist_s;

/* Snapshots are kept in a doubly-linked list in the DB. */
/* Each snapshot corresponds to a particular sequence number. */
typedef struct ldb_snapshot_s {
  /* ldb_snapshot_t is kept in a doubly-linked circular list. The
     ldb_snaplist_t implementation operates on the next/previous
     fields directly. */
  ldb_seqnum_t sequence;
  struct ldb_snapshot_s *prev;
  struct ldb_snapshot_s *next;
#ifndef NDEBUG
  struct ldb_snaplist_s *list;
#endif
} ldb_snapshot_t;

typedef struct ldb_snaplist_s {
  /* Dummy head of doubly-linked list of snapshots. */
  ldb_snapshot_t head;
} ldb_snaplist_t;

/*
 * Snapshot List
 */

LDB_UNUSED static void
ldb_snaplist_init(ldb_snaplist_t *list) {
  list->head.sequence = 0;
  list->head.prev = &list->head;
  list->head.next = &list->head;
#ifndef NDEBUG
  list->head.list = NULL;
#endif
}

LDB_UNUSED static int
ldb_snaplist_empty(const ldb_snaplist_t *list) {
  return list->head.next == &list->head;
}

LDB_UNUSED static ldb_snapshot_t *
ldb_snaplist_oldest(const ldb_snaplist_t *list) {
  assert(!ldb_snaplist_empty(list));
  return list->head.next;
}

LDB_UNUSED static ldb_snapshot_t *
ldb_snaplist_newest(const ldb_snaplist_t *list) {
  assert(!ldb_snaplist_empty(list));
  return list->head.prev;
}

/* Creates a snapshot and appends it to the end of the list. */
LDB_UNUSED static ldb_snapshot_t *
ldb_snaplist_new(ldb_snaplist_t *list, ldb_seqnum_t sequence) {
  ldb_snapshot_t *snap;

  assert(ldb_snaplist_empty(list)
      || ldb_snaplist_newest(list)->sequence <= sequence);

  snap = ldb_malloc(sizeof(ldb_snapshot_t));

  snap->sequence = sequence;
  snap->next = &list->head;
  snap->prev = list->head.prev;
  snap->prev->next = snap;
  snap->next->prev = snap;

#ifndef NDEBUG
  snap->list = list;
#endif

  return snap;
}

/* Removes a snapshot from this list.
 *
 * The snapshot must have been created by calling ldb_snaplist_new
 * on this list.
 *
 * The snapshot pointer should not be const, because its memory is
 * deallocated. However, that would force us to change release_snapshot(),
 * which is in the API, and currently takes a const snapshot.
 */
LDB_UNUSED static void
ldb_snaplist_delete(ldb_snaplist_t *list, const ldb_snapshot_t *snap) {
#ifndef NDEBUG
  assert(snap->list == list);
#else
  (void)list;
#endif

  snap->prev->next = snap->next;
  snap->next->prev = snap->prev;

  ldb_free((void *)snap);
}

#endif /* LDB_SNAPSHOT_H */
