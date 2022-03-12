/*!
 * vector.h - shallow vector for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 */

#ifndef LDB_VECTOR_H
#define LDB_VECTOR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include "types.h"

/*
 * Vector
 */

void
ldb_vector_init(ldb_vector_t *z);

void
ldb_vector_clear(ldb_vector_t *z);

void
ldb_vector_reset(ldb_vector_t *z);

void
ldb_vector_grow(ldb_vector_t *z, size_t zn);

void
ldb_vector_push(ldb_vector_t *z, const void *x);

void *
ldb_vector_pop(ldb_vector_t *z);

void *
ldb_vector_top(const ldb_vector_t *z);

void
ldb_vector_resize(ldb_vector_t *z, size_t zn);

void
ldb_vector_copy(ldb_vector_t *z, const ldb_vector_t *x);

void
ldb_vector_swap(ldb_vector_t *x, ldb_vector_t *y);

void
ldb_vector_sort(ldb_vector_t *z, int (*cmp)(void *, void *));

#ifdef __cplusplus
}
#endif

#endif /* LDB_VECTOR_H */
