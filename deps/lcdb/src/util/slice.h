/*!
 * slice.h - slice for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on google/leveldb:
 *   Copyright (c) 2011, The LevelDB Authors. All rights reserved.
 *   https://github.com/google/leveldb
 *
 * See LICENSE for more information.
 */

#ifndef LDB_SLICE_H
#define LDB_SLICE_H

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include "coding.h"
#include "extern.h"
#include "internal.h"
#include "types.h"

/*
 * Slice
 */

LDB_EXTERN ldb_slice_t
ldb_slice(const uint8_t *xp, size_t xn);

LDB_EXTERN ldb_slice_t
ldb_string(const char *xp);

#define ldb_slice ldb__slice

LDB_STATIC ldb_slice_t
ldb_slice(const uint8_t *xp, size_t xn) {
  ldb_slice_t z;

  z.data = (uint8_t *)xp;
  z.size = xn;
  z.alloc = 0;

  return z;
}

LDB_STATIC void
ldb_slice_init(ldb_slice_t *z) {
  z->data = NULL;
  z->size = 0;
  z->alloc = 0;
}

LDB_STATIC void
ldb_slice_reset(ldb_slice_t *z) {
  z->data = NULL;
  z->size = 0;
  z->alloc = 0;
}

LDB_STATIC void
ldb_slice_set(ldb_slice_t *z, const uint8_t *xp, size_t xn) {
  z->data = (uint8_t *)xp;
  z->size = xn;
  z->alloc = 0;
}

void
ldb_slice_set_str(ldb_slice_t *z, const char *xp);

void
ldb_slice_copy(ldb_slice_t *z, const ldb_slice_t *x);

uint32_t
ldb_slice_hash(const ldb_slice_t *x);

int
ldb_slice_equal(const ldb_slice_t *x, const ldb_slice_t *y);

LDB_EXTERN int
ldb_slice_compare(const ldb_slice_t *x, const ldb_slice_t *y);

void
ldb_slice_eat(ldb_slice_t *z, size_t xn);

size_t
ldb_slice_size(const ldb_slice_t *x);

uint8_t *
ldb_slice_write(uint8_t *zp, const ldb_slice_t *x);

/* PutLengthPrefixedSlice */
void
ldb_slice_export(ldb_buffer_t *z, const ldb_slice_t *x);

int
ldb_slice_read(ldb_slice_t *z, const uint8_t **xp, size_t *xn);

/* See GetInternalKey in version_edit.cc. */
int
ldb_slice_slurp(ldb_slice_t *z, ldb_slice_t *x);

int
ldb_slice_import(ldb_slice_t *z, const ldb_slice_t *x);

/* See GetLengthPrefixedSlice in memtable.cc. */
LDB_UNUSED static ldb_slice_t
ldb_slice_decode(const uint8_t *xp) {
  uint32_t zn = 0;
  size_t xn = 5;
  ldb_slice_t z;

#ifndef NDEBUG
  if (!ldb_varint32_read(&zn, &xp, &xn))
    assert(0 && "invalid slice prefix");
#else
  ldb_varint32_read(&zn, &xp, &xn);
#endif

  ldb_slice_set(&z, xp, zn);

  return z;
}

#endif /* LDB_SLICE_H */
