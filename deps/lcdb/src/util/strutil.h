/*!
 * strutil.h - string utilities for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on google/leveldb:
 *   Copyright (c) 2011, The LevelDB Authors. All rights reserved.
 *   https://github.com/google/leveldb
 *
 * See LICENSE for more information.
 */

#ifndef LDB_STRUTIL_H
#define LDB_STRUTIL_H

#include <stddef.h>
#include <stdint.h>

/*
 * String
 */

int
ldb_size_int(uint64_t x);

int
ldb_encode_int(char *zp, uint64_t x, int pad);

int
ldb_decode_int(uint64_t *z, const char **xp);

int
ldb_starts_with(const char *xp, const char *yp);

char *
ldb_basename(const char *fname);

int
ldb_dirname(char *buf, size_t size, const char *fname);

int
ldb_join(char *zp, size_t zn, const char *xp, const char *yp);

#endif /* LDB_STRUTIL_H */
