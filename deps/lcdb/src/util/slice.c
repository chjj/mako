/*!
 * slice.c - slice for lcdb
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
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "buffer.h"
#include "coding.h"
#include "hash.h"
#include "internal.h"
#include "slice.h"

/*
 * Slice
 */

#undef ldb_slice

ldb_slice_t
ldb_slice(const uint8_t *xp, size_t xn) {
  ldb_slice_t z;

  z.data = (uint8_t *)xp;
  z.size = xn;
  z.alloc = 0;

  return z;
}

ldb_slice_t
ldb_string(const char *xp) {
  return ldb_slice((const uint8_t *)xp, strlen(xp));
}

void
ldb_slice_set_str(ldb_slice_t *z, const char *xp) {
  ldb_slice_set(z, (const uint8_t *)xp, strlen(xp));
}

void
ldb_slice_copy(ldb_slice_t *z, const ldb_slice_t *x) {
  ldb_slice_set(z, x->data, x->size);
}

uint32_t
ldb_slice_hash(const ldb_slice_t *x) {
  return ldb_hash(x->data, x->size, 0);
}

int
ldb_slice_equal(const ldb_slice_t *x, const ldb_slice_t *y) {
  if (x->size != y->size)
    return 0;

  if (x->size == 0)
    return 1;

  return memcmp(x->data, y->data, y->size) == 0;
}

size_t
ldb_slice_size(const ldb_slice_t *x) {
  return ldb_varint32_size(x->size) + x->size;
}

uint8_t *
ldb_slice_write(uint8_t *zp, const ldb_slice_t *x) {
  zp = ldb_varint32_write(zp, x->size);
  zp = ldb_raw_write(zp, x->data, x->size);
  return zp;
}

void
ldb_slice_export(ldb_buffer_t *z, const ldb_slice_t *x) {
  uint8_t *zp = ldb_buffer_expand(z, 5 + x->size);
  size_t xn = ldb_slice_write(zp, x) - zp;

  z->size += xn;
}

int
ldb_slice_read(ldb_slice_t *z, const uint8_t **xp, size_t *xn) {
  const uint8_t *zp;
  uint32_t zn;

  if (!ldb_varint32_read(&zn, xp, xn))
    return 0;

  if (!ldb_zraw_read(&zp, zn, xp, xn))
    return 0;

  ldb_slice_set(z, zp, zn);

  return 1;
}

int
ldb_slice_slurp(ldb_slice_t *z, ldb_slice_t *x) {
  return ldb_slice_read(z, (const uint8_t **)&x->data, &x->size);
}

int
ldb_slice_import(ldb_slice_t *z, const ldb_slice_t *x) {
  ldb_slice_t tmp = *x;
  return ldb_slice_slurp(z, &tmp);
}

int
ldb_equal(const ldb_slice_t *x, const ldb_slice_t *y) {
  return ldb_slice_equal(x, y);
}
