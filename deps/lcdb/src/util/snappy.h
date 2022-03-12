/*!
 * snappy.h - snappy for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on golang/snappy:
 *   Copyright (c) 2011 The Snappy-Go Authors. All rights reserved.
 *   https://github.com/golang/snappy
 *
 * See LICENSE for more information.
 */

#ifndef LDB_SNAPPY_H
#define LDB_SNAPPY_H

#include <stddef.h>
#include <stdint.h>

/*
 * Snappy
 */

#define snappy_encode_size ldb_snappy_encode_size
#define snappy_encode ldb_snappy_encode
#define snappy_decode_size ldb_snappy_decode_size
#define snappy_decode ldb_snappy_decode

int
snappy_encode_size(size_t *zn, size_t xn);

size_t
snappy_encode(uint8_t *zp, const uint8_t *xp, size_t xn);

int
snappy_decode_size(size_t *zn, const uint8_t *xp, size_t xn);

int
snappy_decode(uint8_t *zp, const uint8_t *xp, size_t xn);

#endif /* LDB_SNAPPY_H */
