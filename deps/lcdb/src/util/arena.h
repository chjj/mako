/*!
 * arena.h - arena for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on google/leveldb:
 *   Copyright (c) 2011, The LevelDB Authors. All rights reserved.
 *   https://github.com/google/leveldb
 *
 * See LICENSE for more information.
 */

#ifndef LDB_ARENA_H
#define LDB_ARENA_H

#include <stddef.h>
#include <stdint.h>
#include "atomic.h"
#include "internal.h"
#include "types.h"

/*
 * Types
 */

typedef struct ldb_arena_s {
  /* Allocation state. */
  uint8_t *data;
  size_t left;
  /* Total memory usage of the arena. */
  ldb_atomic(size_t) usage;
  /* Array of allocated memory blocks. */
  ldb_vector_t blocks;
} ldb_arena_t;

/*
 * Arena
 */

void
ldb_arena_init(ldb_arena_t *arena);

void
ldb_arena_clear(ldb_arena_t *arena);

/* Returns an estimate of the total memory usage of data allocated
   by the arena. */
size_t
ldb_arena_usage(const ldb_arena_t *arena);

/* Return a pointer to a newly allocated memory block of "bytes" bytes. */
void *
ldb_arena_alloc(ldb_arena_t *arena, size_t size);

/* Allocate memory with the normal alignment guarantees provided by malloc. */
LDB_MALLOC void *
ldb_arena_alloc_aligned(ldb_arena_t *arena, size_t size);

#endif /* LDB_ARENA_H */
