/*!
 * random.h - random number generator for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on google/leveldb:
 *   Copyright (c) 2011, The LevelDB Authors. All rights reserved.
 *   https://github.com/google/leveldb
 *
 * See LICENSE for more information.
 */

#ifndef LDB_RANDOM_H
#define LDB_RANDOM_H

#include <stdint.h>

/* A very simple random number generator.  Not especially good at
   generating truly random bits, but good enough for our needs in this
   package. */

typedef struct ldb_rand_s {
  uint32_t seed;
} ldb_rand_t;

void
ldb_rand_init(ldb_rand_t *rnd, uint32_t seed);

uint32_t
ldb_rand_next(ldb_rand_t *rnd);

uint32_t
ldb_rand_uniform(ldb_rand_t *rnd, uint32_t n);

uint32_t
ldb_rand_one_in(ldb_rand_t *rnd, uint32_t n);

uint32_t
ldb_rand_skewed(ldb_rand_t *rnd, int max_log);

#endif /* LDB_RANDOM_H */
