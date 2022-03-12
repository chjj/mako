/*!
 * array.h - integer vector for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 */

#ifndef LDB_ARRAY_H
#define LDB_ARRAY_H

#include <stddef.h>
#include <stdint.h>
#include "types.h"

/*
 * Integer Vector
 */

void
ldb_array_init(ldb_array_t *z);

void
ldb_array_clear(ldb_array_t *z);

void
ldb_array_reset(ldb_array_t *z);

void
ldb_array_grow(ldb_array_t *z, size_t zn);

void
ldb_array_push(ldb_array_t *z, int64_t x);

int64_t
ldb_array_pop(ldb_array_t *z);

int64_t
ldb_array_top(const ldb_array_t *z);

void
ldb_array_resize(ldb_array_t *z, size_t zn);

void
ldb_array_copy(ldb_array_t *z, const ldb_array_t *x);

void
ldb_array_swap(ldb_array_t *x, ldb_array_t *y);

void
ldb_array_sort(ldb_array_t *z, int (*cmp)(int64_t, int64_t));

#endif /* LDB_ARRAY_H */
