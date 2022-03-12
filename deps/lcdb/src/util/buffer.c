/*!
 * buffer.c - buffer for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "buffer.h"
#include "coding.h"
#include "hash.h"
#include "internal.h"
#include "memcmp.h"
#include "strutil.h"

/*
 * Buffer
 */

void
ldb_buffer_init(ldb_buffer_t *z) {
  z->data = NULL;
  z->size = 0;
  z->alloc = 0;
}

void
ldb_buffer_clear(ldb_buffer_t *z) {
  if (z->alloc > 0)
    ldb_free(z->data);

  z->data = NULL;
  z->size = 0;
  z->alloc = 0;
}

void
ldb_buffer_reset(ldb_buffer_t *z) {
  z->size = 0;
}

uint8_t *
ldb_buffer_grow(ldb_buffer_t *z, size_t zn) {
  if (zn > z->alloc) {
    z->data = (uint8_t *)ldb_realloc(z->data, zn);
    z->alloc = zn;
  }

  return z->data;
}

uint8_t *
ldb_buffer_expand(ldb_buffer_t *z, size_t xn) {
  size_t zn = z->size + xn;

  if (zn > z->alloc) {
    size_t alloc = (z->alloc * 3) / 2;

    if (alloc < zn)
      alloc = zn;

    z->data = (uint8_t *)ldb_realloc(z->data, alloc);
    z->alloc = alloc;
  }

  if (z->alloc == 0)
    return NULL;

  return z->data + z->size;
}

uint8_t *
ldb_buffer_resize(ldb_buffer_t *z, size_t zn) {
  ldb_buffer_grow(z, zn);
  z->size = zn;
  return z->data;
}

void
ldb_buffer_set(ldb_buffer_t *z, const uint8_t *xp, size_t xn) {
  ldb_buffer_grow(z, xn);

  if (xn > 0)
    memcpy(z->data, xp, xn);

  z->size = xn;
}

void
ldb_buffer_set_str(ldb_buffer_t *z, const char *xp) {
  ldb_buffer_set(z, (const uint8_t *)xp, strlen(xp));
}

void
ldb_buffer_copy(ldb_buffer_t *z, const ldb_buffer_t *x) {
  ldb_buffer_set(z, x->data, x->size);
}

void
ldb_buffer_swap(ldb_buffer_t *x, ldb_buffer_t *y) {
  ldb_buffer_t t = *x;
  *x = *y;
  *y = t;
}

void
ldb_buffer_roset(ldb_buffer_t *z, const uint8_t *xp, size_t xn) {
  z->data = (uint8_t *)xp;
  z->size = xn;
  z->alloc = 0;
}

void
ldb_buffer_rocopy(ldb_buffer_t *z, const ldb_buffer_t *x) {
  ldb_buffer_roset(z, x->data, x->size);
}

void
ldb_buffer_rwset(ldb_buffer_t *z, uint8_t *zp, size_t zn) {
  z->data = zp;
  z->size = 0;
  z->alloc = zn;
}

uint32_t
ldb_buffer_hash(const ldb_buffer_t *x) {
  return ldb_hash(x->data, x->size, 0);
}

int
ldb_buffer_equal(const ldb_buffer_t *x, const ldb_buffer_t *y) {
  if (x->size != y->size)
    return 0;

  if (x->size == 0)
    return 1;

  return memcmp(x->data, y->data, y->size) == 0;
}

int
ldb_buffer_compare(const ldb_buffer_t *x, const ldb_buffer_t *y) {
  return ldb_memcmp4(x->data, x->size, y->data, y->size);
}

void
ldb_buffer_push(ldb_buffer_t *z, int x) {
  if (z->size == z->alloc)
    ldb_buffer_grow(z, (z->alloc * 3) / 2 + (z->alloc <= 1));

  z->data[z->size++] = x & 0xff;
}

void
ldb_buffer_append(ldb_buffer_t *z, const uint8_t *xp, size_t xn) {
  uint8_t *zp = ldb_buffer_expand(z, xn);

  if (xn > 0)
    memcpy(zp, xp, xn);

  z->size += xn;
}

void
ldb_buffer_concat(ldb_buffer_t *z, const ldb_slice_t *x) {
  ldb_buffer_append(z, x->data, x->size);
}

void
ldb_buffer_string(ldb_buffer_t *z, const char *xp) {
  ldb_buffer_append(z, (const uint8_t *)xp, strlen(xp));
}

void
ldb_buffer_number(ldb_buffer_t *z, uint64_t x) {
  uint8_t *zp = ldb_buffer_expand(z, 21);

  z->size += ldb_encode_int((char *)zp, x, 0);
}

void
ldb_buffer_escape(ldb_buffer_t *z, const ldb_slice_t *x) {
  uint8_t *zp = ldb_buffer_expand(z, x->size * 4 + 1);
  size_t i;

#define nibble(x) ((x) < 10 ? (x) + '0' : (x) - 10 + 'a')

  for (i = 0; i < x->size; i++) {
    int ch = x->data[i];

    if (ch >= ' ' && ch <= '~') {
      *zp++ = ch;
    } else {
      *zp++ = '\\';
      *zp++ = 'x';
      *zp++ = nibble(ch >> 4);
      *zp++ = nibble(ch & 15);
    }
  }

#undef nibble

  z->size = zp - z->data;
}

uint8_t *
ldb_buffer_pad(ldb_buffer_t *z, size_t xn) {
  uint8_t *zp = ldb_buffer_expand(z, xn);

  if (xn > 0)
    memset(zp, 0, xn);

  z->size += xn;

  return zp;
}

void
ldb_buffer_fixed32(ldb_buffer_t *z, uint32_t x) {
  uint8_t *zp = ldb_buffer_expand(z, 4);

  ldb_fixed32_write(zp, x);

  z->size += 4;
}

void
ldb_buffer_fixed64(ldb_buffer_t *z, uint64_t x) {
  uint8_t *zp = ldb_buffer_expand(z, 8);

  ldb_fixed64_write(zp, x);

  z->size += 8;
}

void
ldb_buffer_varint32(ldb_buffer_t *z, uint32_t x) {
  uint8_t *zp = ldb_buffer_expand(z, 5);
  size_t xn = ldb_varint32_write(zp, x) - zp;

  z->size += xn;
}

void
ldb_buffer_varint64(ldb_buffer_t *z, uint64_t x) {
  uint8_t *zp = ldb_buffer_expand(z, 10);
  size_t xn = ldb_varint64_write(zp, x) - zp;

  z->size += xn;
}

size_t
ldb_buffer_size(const ldb_buffer_t *x) {
  return ldb_varint32_size(x->size) + x->size;
}

uint8_t *
ldb_buffer_write(uint8_t *zp, const ldb_buffer_t *x) {
  zp = ldb_varint32_write(zp, x->size);
  zp = ldb_raw_write(zp, x->data, x->size);
  return zp;
}

void
ldb_buffer_export(ldb_buffer_t *z, const ldb_buffer_t *x) {
  uint8_t *zp = ldb_buffer_expand(z, 5 + x->size);
  size_t xn = ldb_buffer_write(zp, x) - zp;

  z->size += xn;
}

int
ldb_buffer_read(ldb_buffer_t *z, const uint8_t **xp, size_t *xn) {
  const uint8_t *zp;
  uint32_t zn;

  if (!ldb_varint32_read(&zn, xp, xn))
    return 0;

  if (!ldb_zraw_read(&zp, zn, xp, xn))
    return 0;

  ldb_buffer_set(z, zp, zn);

  return 1;
}

int
ldb_buffer_slurp(ldb_buffer_t *z, ldb_slice_t *x) {
  return ldb_buffer_read(z, (const uint8_t **)&x->data, &x->size);
}

int
ldb_buffer_import(ldb_buffer_t *z, const ldb_slice_t *x) {
  ldb_slice_t tmp = *x;
  return ldb_buffer_slurp(z, &tmp);
}
