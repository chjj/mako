/*!
 * hash.h - hash for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on google/leveldb:
 *   Copyright (c) 2011, The LevelDB Authors. All rights reserved.
 *   https://github.com/google/leveldb
 *
 * See LICENSE for more information.
 */

#ifndef LDB_HASH_H
#define LDB_HASH_H

#include <stddef.h>
#include <stdint.h>

/*
 * Hash
 */

uint32_t
ldb_hash(const uint8_t *data, size_t size, uint32_t seed);

#endif /* LDB_HASH_H */
