/*!
 * random.c - random number generator for lcdb
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
#include "internal.h"
#include "random.h"

void
ldb_rand_init(ldb_rand_t *rnd, uint32_t seed) {
  rnd->seed = seed & 0x7fffffff;

  /* Avoid bad seeds. */
  if (rnd->seed == 0 || rnd->seed == 2147483647)
    rnd->seed = 1;
}

uint32_t
ldb_rand_next(ldb_rand_t *rnd) {
  static const uint32_t M = 2147483647; /* 2^31-1 */
  static const uint64_t A = 16807;      /* bits 14, 8, 7, 5, 2, 1, 0 */

  /* We are computing
   *
   *   seed = (seed * A) % M, where M = 2^31-1
   *
   * seed must not be zero or M, or else all subsequent computed values
   * will be zero or M respectively. For all other values, seed will end
   * up cycling through every number in [1,M-1].
   */
  uint64_t product = rnd->seed * A;

  /* Compute (product % M) using the fact that ((x << 31) % M) == x. */
  rnd->seed = (uint32_t)((product >> 31) + (product & M));

  /* The first reduction may overflow by 1 bit, so we may need to
     repeat. mod == M is not possible; using > allows the faster
     sign-bit-based test. */
  if (rnd->seed > M)
    rnd->seed -= M;

  return rnd->seed;
}

uint32_t
ldb_rand_uniform(ldb_rand_t *rnd, uint32_t n) {
  if (UNLIKELY(n == 0))
    return 0;

  return ldb_rand_next(rnd) % n;
}

int
ldb_rand_one_in(ldb_rand_t *rnd, uint32_t n) {
  return ldb_rand_uniform(rnd, n) == 0;
}

uint32_t
ldb_rand_skewed(ldb_rand_t *rnd, int max_log) {
  int shift = ldb_rand_uniform(rnd, max_log + 1);
  return ldb_rand_uniform(rnd, UINT32_C(1) << shift);
}
