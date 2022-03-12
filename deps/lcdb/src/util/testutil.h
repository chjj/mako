/*!
 * testutil.h - test utilities for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on google/leveldb:
 *   Copyright (c) 2011, The LevelDB Authors. All rights reserved.
 *   https://github.com/google/leveldb
 *
 * See LICENSE for more information.
 */

#ifndef LDB_TESTUTIL_H
#define LDB_TESTUTIL_H

#include <stddef.h>
#include <stdint.h>

#include "internal.h"
#include "types.h"

/*
 * Types
 */

struct ldb_rand_s;

/*
 * Assertions
 */

#undef ASSERT

#define ASSERT(expr) do {                       \
  if (UNLIKELY(!(expr)))                        \
    ldb_assert_fail(__FILE__, __LINE__, #expr); \
} while (0)

#define ASSERT_EQ(x, y) ASSERT(strcmp(x, y) == 0)
#define ASSERT_NE(x, y) ASSERT(strcmp(x, y) != 0)

/*
 * Test Utils
 */

/* Returns the random seed used at the start of the current test run. */
uint32_t
ldb_random_seed(void);

/* Store in *dst a random string of length "len" and return a slice that
   references the generated data. */
ldb_slice_t *
ldb_random_string(ldb_buffer_t *dst, struct ldb_rand_s *rnd, size_t len);

/* Return a random key with the specified length that may contain interesting
   characters (e.g. \x00, \xff, etc.). */
ldb_slice_t *
ldb_random_key(ldb_buffer_t *dst, struct ldb_rand_s *rnd, size_t len);

/* Store in *dst a string of length "len" that will compress to
   "N*compressed_fraction" bytes and return a slice that references
   the generated data. */
ldb_slice_t *
ldb_compressible_string(ldb_buffer_t *dst,
                        struct ldb_rand_s *rnd,
                        double compressed_fraction,
                        size_t len);

#endif /* LDB_TESTUTIL_H */
