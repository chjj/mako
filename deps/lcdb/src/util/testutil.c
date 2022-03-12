/*!
 * testutil.c - test utilities for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on google/leveldb:
 *   Copyright (c) 2011, The LevelDB Authors. All rights reserved.
 *   https://github.com/google/leveldb
 *
 * See LICENSE for more information.
 */

#include <stdint.h>
#include <stdlib.h>

#include "buffer.h"
#include "random.h"
#include "slice.h"
#include "testutil.h"

/*
 * Test Utils
 */

uint32_t
ldb_random_seed(void) {
  return rand() & 0x7fffffff;
}

ldb_slice_t *
ldb_random_string(ldb_buffer_t *dst, ldb_rand_t *rnd, size_t len) {
  size_t i;

  ldb_buffer_reset(dst);
  ldb_buffer_grow(dst, len + 1);

  for (i = 0; i < len; i++)
    dst->data[i] = ' ' + ldb_rand_uniform(rnd, 95);

  dst->data[len] = '\0';
  dst->size = len;

  return dst;
}

ldb_slice_t *
ldb_random_key(ldb_buffer_t *dst, ldb_rand_t *rnd, size_t len) {
  /* Make sure to generate a wide variety of characters so we
     test the boundary conditions for short-key optimizations. */
  static const char test_chars[] = {'\1', '\2', 'a',    'b',    'c',
                                    'd',  'e',  '\xfd', '\xfe', '\xff'};
  size_t i;

  ldb_buffer_reset(dst);
  ldb_buffer_grow(dst, len + 1);

  for (i = 0; i < len; i++) {
    uint32_t n = ldb_rand_uniform(rnd, sizeof(test_chars));

    dst->data[i] = test_chars[n];
  }

  dst->data[len] = '\0';
  dst->size = len;

  return dst;
}

ldb_slice_t *
ldb_compressible_string(ldb_buffer_t *dst,
                        ldb_rand_t *rnd,
                        double compressed_fraction,
                        size_t len) {
  size_t chunklen = (size_t)(len * compressed_fraction);
  ldb_buffer_t chunk;

  if (chunklen < 1)
    chunklen = 1;

  ldb_buffer_init(&chunk);
  ldb_random_string(&chunk, rnd, chunklen);

  /* Duplicate the random data until we have filled "len" bytes. */
  ldb_buffer_reset(dst);
  ldb_buffer_grow(dst, len + chunk.size + 1);

  while (dst->size < len)
    ldb_buffer_concat(dst, &chunk);

  dst->data[len] = '\0';
  dst->size = len;

  ldb_buffer_clear(&chunk);

  return dst;
}
