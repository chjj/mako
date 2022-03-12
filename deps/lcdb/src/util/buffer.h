/*!
 * buffer.h - buffer for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 */

#ifndef LDB_BUFFER_H
#define LDB_BUFFER_H

#include <stddef.h>
#include <stdint.h>
#include "types.h"

/*
 * Buffer
 */

void
ldb_buffer_init(ldb_buffer_t *z);

void
ldb_buffer_clear(ldb_buffer_t *z);

void
ldb_buffer_reset(ldb_buffer_t *z);

uint8_t *
ldb_buffer_grow(ldb_buffer_t *z, size_t zn);

uint8_t *
ldb_buffer_expand(ldb_buffer_t *z, size_t xn);

uint8_t *
ldb_buffer_resize(ldb_buffer_t *z, size_t zn);

void
ldb_buffer_set(ldb_buffer_t *z, const uint8_t *xp, size_t xn);

void
ldb_buffer_set_str(ldb_buffer_t *z, const char *xp);

void
ldb_buffer_copy(ldb_buffer_t *z, const ldb_buffer_t *x);

void
ldb_buffer_swap(ldb_buffer_t *x, ldb_buffer_t *y);

void
ldb_buffer_roset(ldb_buffer_t *z, const uint8_t *xp, size_t xn);

void
ldb_buffer_rocopy(ldb_buffer_t *z, const ldb_buffer_t *x);

void
ldb_buffer_rwset(ldb_buffer_t *z, uint8_t *zp, size_t zn);

uint32_t
ldb_buffer_hash(const ldb_buffer_t *x);

int
ldb_buffer_equal(const ldb_buffer_t *x, const ldb_buffer_t *y);

int
ldb_buffer_compare(const ldb_buffer_t *x, const ldb_buffer_t *y);

void
ldb_buffer_push(ldb_buffer_t *z, int x);

void
ldb_buffer_append(ldb_buffer_t *z, const uint8_t *xp, size_t xn);

void
ldb_buffer_concat(ldb_buffer_t *z, const ldb_slice_t *x);

void
ldb_buffer_string(ldb_buffer_t *z, const char *xp);

void
ldb_buffer_number(ldb_buffer_t *z, uint64_t x);

void
ldb_buffer_escape(ldb_buffer_t *z, const ldb_slice_t *x);

uint8_t *
ldb_buffer_pad(ldb_buffer_t *z, size_t xn);

void
ldb_buffer_fixed32(ldb_buffer_t *z, uint32_t x);

void
ldb_buffer_fixed64(ldb_buffer_t *z, uint64_t x);

void
ldb_buffer_varint32(ldb_buffer_t *z, uint32_t x);

void
ldb_buffer_varint64(ldb_buffer_t *z, uint64_t x);

size_t
ldb_buffer_size(const ldb_buffer_t *x);

uint8_t *
ldb_buffer_write(uint8_t *zp, const ldb_buffer_t *x);

/* PutLengthPrefixedSlice */
void
ldb_buffer_export(ldb_buffer_t *z, const ldb_buffer_t *x);

int
ldb_buffer_read(ldb_buffer_t *z, const uint8_t **xp, size_t *xn);

/* See GetInternalKey in version_edit.cc. */
int
ldb_buffer_slurp(ldb_buffer_t *z, ldb_slice_t *x);

int
ldb_buffer_import(ldb_buffer_t *z, const ldb_slice_t *x);

#endif /* LDB_BUFFER_H */
