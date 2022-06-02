/*!
 * arena.c - arena for lcdb
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
#include "arena.h"
#include "atomic.h"
#include "internal.h"
#include "vector.h"

/*
 * Constants
 */

#define LDB_ARENA_BLOCK 4096

/*
 * Arena
 */

void
ldb_arena_init(ldb_arena_t *arena) {
  arena->data = NULL;
  arena->left = 0;
  arena->usage = 0;

  ldb_vector_init(&arena->blocks);
}

void
ldb_arena_clear(ldb_arena_t *arena) {
  size_t i;

  for (i = 0; i < arena->blocks.length; i++)
    ldb_free(arena->blocks.items[i]);

  ldb_vector_clear(&arena->blocks);
}

size_t
ldb_arena_usage(const ldb_arena_t *arena) {
  return ldb_atomic_load(&arena->usage, ldb_order_relaxed);
}

static void *
ldb_arena_alloc_block(ldb_arena_t *arena, size_t size) {
  void *result = ldb_malloc(size);

  ldb_vector_push(&arena->blocks, result);

  ldb_atomic_fetch_add(&arena->usage,
                       size + sizeof(void *),
                       ldb_order_relaxed);

  return result;
}

static void *
ldb_arena_alloc_fallback(ldb_arena_t *arena, size_t size) {
  void *result;

  if (size > LDB_ARENA_BLOCK / 4) {
    /* Object is more than a quarter of our block size.
       Allocate it separately to avoid wasting too much
       space in leftover bytes. */
    return ldb_arena_alloc_block(arena, size);
  }

  /* We waste the remaining space in the current block. */
  arena->data = ldb_arena_alloc_block(arena, LDB_ARENA_BLOCK);
  arena->left = LDB_ARENA_BLOCK;

  result = arena->data;

  arena->data += size;
  arena->left -= size;

  return result;
}

void *
ldb_arena_alloc(ldb_arena_t *arena, size_t size) {
  /* The semantics of what to return are a bit messy if we allow
     0-byte allocations, so we disallow them here (we don't need
     them for our internal use). */
  assert(size > 0);

  if (size <= arena->left) {
    void *result = arena->data;

    arena->data += size;
    arena->left -= size;

    return result;
  }

  return ldb_arena_alloc_fallback(arena, size);
}

LDB_MALLOC void *
ldb_arena_alloc_aligned(ldb_arena_t *arena, size_t size) {
  static const int align = sizeof(void *) > 8 ? sizeof(void *) : 8;
  size_t current_mod = (uintptr_t)((void *)arena->data) & (align - 1);
  size_t slop = (current_mod == 0 ? 0 : align - current_mod);
  size_t needed = size + slop;
  void *result;

  assert((align & (align - 1)) == 0);

  if (needed <= arena->left) {
    result = arena->data + slop;

    arena->data += needed;
    arena->left -= needed;

    assert(((uintptr_t)result & (align - 1)) == 0);
  } else {
    /* alloc_fallback always returns aligned memory. */
    result = ldb_arena_alloc_fallback(arena, size);
  }

  return result;
}
