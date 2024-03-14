/*!
 * cache.c - lru cache for lcdb
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

#include "cache.h"
#include "hash.h"
#include "internal.h"
#include "port.h"
#include "slice.h"

/* LRU cache implementation
 *
 * Cache entries have an "in_cache" boolean indicating whether the cache has a
 * reference on the entry. The only ways that this can become false without the
 * entry being passed to its "deleter" are via erase(), via insert() when
 * an element with a duplicate key is inserted, or on destruction of the cache.
 *
 * The cache keeps two linked lists of items in the cache. All items in the
 * cache are in one list or the other, and never both. Items still referenced
 * by clients but erased from the cache are in neither list. The lists are:
 *
 * - in-use: contains the items currently referenced by clients, in no
 *   particular order. (This list is used for invariant checking. If we
 *   removed the check, elements that would otherwise be on this list could be
 *   left as disconnected singleton lists.)
 *
 * - LRU: contains the items not currently referenced by clients, in LRU order
 *
 * Elements are moved between these lists by the ref() and unref() methods,
 * when they detect an element in the cache acquiring or losing its only
 * external reference.
 */

/*
 * Constants
 */

#define LDB_SHARD_BITS 4
#define LDB_SHARDS (1 << LDB_SHARD_BITS)

/*
 * LRUHandle
 */

#define lru_handle_s ldb_entry_s

/* An entry is a variable length heap-allocated structure. Entries
   are kept in a circular doubly linked list ordered by access time. */
typedef struct lru_handle_s {
  void *value;
  void (*deleter)(const ldb_slice_t *key, void *value);
  struct lru_handle_s *next_hash;
  struct lru_handle_s *next;
  struct lru_handle_s *prev;
  size_t charge;
  size_t key_length;
  int in_cache;        /* Whether entry is in the cache. */
  uint32_t refs;       /* References, including cache reference, if present. */
  uint32_t hash;       /* Hash of key(); used for fast sharding & comparisons */
  uint8_t key_data[1]; /* Beginning of key. */
} lru_handle_t;

static ldb_slice_t
lru_handle_key(const lru_handle_t *handle) {
  ldb_slice_t key;

  /* next is only equal to this if the LRU handle
     is the list head of an empty list. List heads
     never have meaningful keys. */
  assert(handle->next != handle);

  ldb_slice_set(&key, handle->key_data, handle->key_length);

  return key;
}

static int
lru_handle_equal(const lru_handle_t *x, const ldb_slice_t *y) {
  assert(x->next != x);

  if (x->key_length != y->size)
    return 0;

  return memcmp(x->key_data, y->data, y->size) == 0;
}

/*
 * HandleTable
 */

typedef struct lru_table_s {
  /* The table consists of an array of buckets where each bucket is
     a linked list of cache entries that hash into the bucket. */
  uint32_t length;
  uint32_t elems;
  lru_handle_t **list;
} lru_table_t;

/* Return a pointer to slot that points to a cache entry that
 * matches key/hash. If there is no such cache entry, return a
 * pointer to the trailing slot in the corresponding linked list.
 */
static lru_handle_t **
lru_table_find(lru_table_t *tbl, const ldb_slice_t *key, uint32_t hash) {
  lru_handle_t **ptr = &tbl->list[hash & (tbl->length - 1)];

  while (*ptr != NULL && ((*ptr)->hash != hash || !lru_handle_equal(*ptr, key)))
    ptr = &(*ptr)->next_hash;

  return ptr;
}

static void
lru_table_resize(lru_table_t *tbl) {
  lru_handle_t **new_list;
  uint32_t new_length = 4;
  uint32_t count = 0;
  uint32_t i;

  while (new_length < tbl->elems)
    new_length *= 2;

  new_list = ldb_malloc(new_length * sizeof(lru_handle_t *));

  memset(new_list, 0, sizeof(new_list[0]) * new_length);

  for (i = 0; i < tbl->length; i++) {
    lru_handle_t *h = tbl->list[i];

    while (h != NULL) {
      lru_handle_t *next = h->next_hash;
      uint32_t hash = h->hash;
      lru_handle_t **ptr;

      ptr = &new_list[hash & (new_length - 1)];
      h->next_hash = *ptr;
      *ptr = h;
      h = next;
      count++;
    }
  }

  assert(tbl->elems == count);

  if (tbl->list != NULL)
    ldb_free(tbl->list);

  tbl->list = new_list;
  tbl->length = new_length;
}

static void
lru_table_init(lru_table_t *tbl) {
  tbl->length = 0;
  tbl->elems = 0;
  tbl->list = NULL;

  lru_table_resize(tbl);
}

static void
lru_table_clear(lru_table_t *tbl) {
  if (tbl->list != NULL)
    ldb_free(tbl->list);
}

static lru_handle_t *
lru_table_lookup(lru_table_t *tbl, const ldb_slice_t *key, uint32_t hash) {
  return *lru_table_find(tbl, key, hash);
}

static lru_handle_t *
lru_table_insert(lru_table_t *tbl, lru_handle_t *h) {
  ldb_slice_t key = lru_handle_key(h);
  lru_handle_t **ptr = lru_table_find(tbl, &key, h->hash);
  lru_handle_t *old = *ptr;

  h->next_hash = (old == NULL ? NULL : old->next_hash);

  *ptr = h;

  if (old == NULL) {
    ++tbl->elems;
    if (tbl->elems > tbl->length) {
      /* Since each cache entry is fairly large, we aim
         for a small average linked list length (<= 1). */
      lru_table_resize(tbl);
    }
  }

  return old;
}

static lru_handle_t *
lru_table_remove(lru_table_t *tbl, const ldb_slice_t *key, uint32_t hash) {
  lru_handle_t **ptr = lru_table_find(tbl, key, hash);
  lru_handle_t *result = *ptr;

  if (result != NULL) {
    *ptr = result->next_hash;
    --tbl->elems;
  }

  return result;
}

/*
 * LRU
 */

/* A single shard of sharded cache. */
typedef struct lru_shard_s {
  /* Initialized before use. */
  size_t capacity;

  /* mutex protects the following state. */
  ldb_mutex_t mutex;
  size_t usage;

  /* Dummy head of LRU list. */
  /* list.prev is newest entry, list.next is oldest entry. */
  /* Entries have refs==1 and in_cache==1. */
  lru_handle_t list;

  /* Dummy head of in-use list. */
  /* Entries are in use by clients, and have refs >= 2 and in_cache==1. */
  lru_handle_t in_use;

  lru_table_t table;
} lru_shard_t;

static size_t
lru_shard_usage(lru_shard_t *lru) {
  size_t usage;
  ldb_mutex_lock(&lru->mutex);
  usage = lru->usage;
  ldb_mutex_unlock(&lru->mutex);
  return usage;
}

static void
lru_shard_append(lru_handle_t *list, lru_handle_t *e) {
  /* Make "e" newest entry by inserting just before *list */
  e->next = list;
  e->prev = list->prev;
  e->prev->next = e;
  e->next->prev = e;
}

static void
lru_shard_remove(lru_handle_t *e) {
  e->next->prev = e->prev;
  e->prev->next = e->next;
}

static void
lru_shard_ref(lru_shard_t *lru, lru_handle_t *e) {
  if (e->refs == 1 && e->in_cache) { /* If on lru->list, move to lru->in_use. */
    lru_shard_remove(e);
    lru_shard_append(&lru->in_use, e);
  }
  e->refs++;
}

static void
lru_shard_unref(lru_shard_t *lru, lru_handle_t *e) {
  assert(e->refs > 0);

  e->refs--;

  if (e->refs == 0) { /* Deallocate. */
    ldb_slice_t key = lru_handle_key(e);

    assert(!e->in_cache);

    e->deleter(&key, e->value);

    ldb_free(e);
  } else if (e->in_cache && e->refs == 1) {
    /* No longer in use; move to lru->list. */
    lru_shard_remove(e);
    lru_shard_append(&lru->list, e);
  }
}

static void
lru_shard_init(lru_shard_t *lru) {
  memset(lru, 0, sizeof(*lru));

  ldb_mutex_init(&lru->mutex);

  lru->capacity = 0;
  lru->usage = 0;

  /* Make empty circular linked lists. */
  lru->list.next = &lru->list;
  lru->list.prev = &lru->list;

  lru->in_use.next = &lru->in_use;
  lru->in_use.prev = &lru->in_use;

  lru_table_init(&lru->table);
}

static void
lru_shard_clear(lru_shard_t *lru) {
  lru_handle_t *e, *next;

  assert(lru->in_use.next == &lru->in_use); /* Error if caller has
                                               an unreleased handle */

  for (e = lru->list.next; e != &lru->list; e = next) {
    next = e->next;

    assert(e->in_cache);

    e->in_cache = 0;

    assert(e->refs == 1); /* Invariant of lru->list. */

    lru_shard_unref(lru, e);
  }

  lru_table_clear(&lru->table);

  ldb_mutex_destroy(&lru->mutex);
}

static lru_handle_t *
lru_shard_lookup(lru_shard_t *lru, const ldb_slice_t *key, uint32_t hash) {
  lru_handle_t *e;

  ldb_mutex_lock(&lru->mutex);

  e = lru_table_lookup(&lru->table, key, hash);

  if (e != NULL)
    lru_shard_ref(lru, e);

  ldb_mutex_unlock(&lru->mutex);

  return e;
}

static void
lru_shard_release(lru_shard_t *lru, lru_handle_t *handle) {
  ldb_mutex_lock(&lru->mutex);
  lru_shard_unref(lru, handle);
  ldb_mutex_unlock(&lru->mutex);
}

/* If e != NULL, finish removing *e from the cache; it has already been
   removed from the hash table. Return whether e != NULL. */
static int
lru_shard_finish(lru_shard_t *lru, lru_handle_t *e) {
  if (e != NULL) {
    assert(e->in_cache);

    lru_shard_remove(e);

    e->in_cache = 0;

    lru->usage -= e->charge;

    lru_shard_unref(lru, e);
  }

  return e != NULL;
}

static void
lru_shard_erase(lru_shard_t *lru, const ldb_slice_t *key, uint32_t hash) {
  ldb_mutex_lock(&lru->mutex);
  lru_shard_finish(lru, lru_table_remove(&lru->table, key, hash));
  ldb_mutex_unlock(&lru->mutex);
}

static void
lru_shard_prune(lru_shard_t *lru) {
  ldb_mutex_lock(&lru->mutex);

  while (lru->list.next != &lru->list) {
    lru_handle_t *e = lru->list.next;
    ldb_slice_t key = lru_handle_key(e);

    assert(e->refs == 1);

    lru_shard_finish(lru,
      lru_table_remove(&lru->table, &key, e->hash));
  }

  ldb_mutex_unlock(&lru->mutex);
}

static lru_handle_t *
lru_shard_insert(lru_shard_t *lru,
                 const ldb_slice_t *key,
                 uint32_t hash,
                 void *value,
                 size_t charge,
                 void (*deleter)(const ldb_slice_t *key, void *value)) {
  lru_handle_t *e;

  ldb_mutex_lock(&lru->mutex);

  e = ldb_malloc(sizeof(lru_handle_t) - 1 + key->size);

  e->value = value;
  e->deleter = deleter;
  e->charge = charge;
  e->key_length = key->size;
  e->hash = hash;
  e->in_cache = 0;
  e->refs = 1; /* For the returned handle. */

  memcpy(e->key_data, key->data, key->size);

  if (lru->capacity > 0) {
    e->refs++; /* For the cache's reference. */
    e->in_cache = 1;
    lru_shard_append(&lru->in_use, e);
    lru->usage += charge;
    lru_shard_finish(lru, lru_table_insert(&lru->table, e));
  } else { /* Don't cache (capacity==0 is supported and turns off caching). */
    /* next is read by key() in an assert, so it must be initialized. */
    e->next = NULL;
  }

  while (lru->usage > lru->capacity && lru->list.next != &lru->list) {
    lru_handle_t *old = lru->list.next;
    ldb_slice_t old_key = lru_handle_key(old);

    assert(old->refs == 1);

    lru_shard_finish(lru,
      lru_table_remove(&lru->table, &old_key, old->hash));
  }

  ldb_mutex_unlock(&lru->mutex);

  return e;
}

/*
 * Cache
 */

struct ldb_lru_s {
  lru_shard_t shard[LDB_SHARDS];
  ldb_mutex_t id_mutex;
  uint64_t last_id;
};

static uint32_t
ldb_lru_hash(const ldb_slice_t *s) {
  return ldb_hash(s->data, s->size, 0);
}

static uint32_t
ldb_lru_shard(uint32_t hash) {
  return hash >> (32 - LDB_SHARD_BITS);
}

ldb_lru_t *
ldb_lru_create(size_t capacity) {
  size_t per_shard = (capacity + LDB_SHARDS - 1) / LDB_SHARDS;
  ldb_lru_t *lru = ldb_malloc(sizeof(ldb_lru_t));
  int i;

  ldb_mutex_init(&lru->id_mutex);

  lru->last_id = 0;

  for (i = 0; i < LDB_SHARDS; i++) {
    lru_shard_init(&lru->shard[i]);

    lru->shard[i].capacity = per_shard;
  }

  return lru;
}

void
ldb_lru_destroy(ldb_lru_t *lru) {
  int i;

  for (i = 0; i < LDB_SHARDS; i++)
    lru_shard_clear(&lru->shard[i]);

  ldb_mutex_destroy(&lru->id_mutex);

  ldb_free(lru);
}

lru_handle_t *
ldb_lru_insert(ldb_lru_t *lru,
               const ldb_slice_t *key,
               void *value,
               size_t charge,
               void (*deleter)(const ldb_slice_t *key, void *value)) {
  uint32_t hash = ldb_lru_hash(key);
  lru_shard_t *shard = &lru->shard[ldb_lru_shard(hash)];
  return lru_shard_insert(shard, key, hash, value, charge, deleter);
}

lru_handle_t *
ldb_lru_lookup(ldb_lru_t *lru, const ldb_slice_t *key) {
  uint32_t hash = ldb_lru_hash(key);
  lru_shard_t *shard = &lru->shard[ldb_lru_shard(hash)];
  return lru_shard_lookup(shard, key, hash);
}

void
ldb_lru_release(ldb_lru_t *lru, lru_handle_t *handle) {
  lru_shard_t *shard = &lru->shard[ldb_lru_shard(handle->hash)];
  lru_shard_release(shard, handle);
}

void
ldb_lru_erase(ldb_lru_t *lru, const ldb_slice_t *key) {
  uint32_t hash = ldb_lru_hash(key);
  lru_shard_t *shard = &lru->shard[ldb_lru_shard(hash)];
  lru_shard_erase(shard, key, hash);
}

void *
ldb_lru_value(lru_handle_t *handle) {
  return handle->value;
}

uint64_t
ldb_lru_id(ldb_lru_t *lru) {
  uint64_t id;
  ldb_mutex_lock(&lru->id_mutex);
  id = ++lru->last_id;
  ldb_mutex_unlock(&lru->id_mutex);
  return id;
}

void
ldb_lru_prune(ldb_lru_t *lru) {
  int i;

  for (i = 0; i < LDB_SHARDS; i++)
    lru_shard_prune(&lru->shard[i]);
}

size_t
ldb_lru_usage(ldb_lru_t *lru) {
  size_t total = 0;
  int i;

  for (i = 0; i < LDB_SHARDS; i++)
    total += lru_shard_usage(&lru->shard[i]);

  return total;
}
