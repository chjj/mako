/*!
 * memtable.h - memtable for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on google/leveldb:
 *   Copyright (c) 2011, The LevelDB Authors. All rights reserved.
 *   https://github.com/google/leveldb
 *
 * See LICENSE for more information.
 */

#ifndef LDB_MEMTABLE_H
#define LDB_MEMTABLE_H

#include "util/types.h"

/*
 * Types
 */

struct ldb_comparator_s;
struct ldb_iter_s;
struct ldb_lkey_s;

typedef struct ldb_memtable_s ldb_memtable_t;

/*
 * MemTable
 */

/* MemTables are reference counted. The initial reference count
   is zero and the caller must call ref() at least once. */
ldb_memtable_t *
ldb_memtable_create(const struct ldb_comparator_s *comparator);

void
ldb_memtable_destroy(ldb_memtable_t *mt);

/* Increase reference count. */
void
ldb_memtable_ref(ldb_memtable_t *mt);

/* Drop reference count. Delete if no more references exist. */
void
ldb_memtable_unref(ldb_memtable_t *mt);

/* Returns an estimate of the number of bytes of data in use by this
   data structure. It is safe to call when memtable is being modified. */
size_t
ldb_memtable_usage(const ldb_memtable_t *mt);

/* Add an entry into memtable that maps key to value at the
   specified sequence number and with the specified type.
   Typically value will be empty if type==LDB_TYPE_DELETION. */
void
ldb_memtable_add(ldb_memtable_t *mt,
                 ldb_seqnum_t sequence,
                 ldb_valtype_t type,
                 const ldb_slice_t *key,
                 const ldb_slice_t *value);

/* If memtable contains a value for key, store it in *value and return true.
   If memtable contains a deletion for key, store a NOTFOUND error
   in *status and return true.
   Else, return false. */
int
ldb_memtable_get(ldb_memtable_t *mt,
                 const struct ldb_lkey_s *key,
                 ldb_buffer_t *value,
                 int *status);

/*
 * MemTable Iterator
 */

/* Return an iterator that yields the contents of the memtable.
 *
 * The caller must ensure that the underlying memtable remains live
 * while the returned iterator is live. The keys returned by this
 * iterator are internal keys encoded by ldb_pkey_export in the
 * src/dbformat.{h,c} module.
 */
struct ldb_iter_s *
ldb_memiter_create(const ldb_memtable_t *mt);

#endif /* LDB_MEMTABLE_H */
