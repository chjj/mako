/*!
 * status.h - error codes for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on google/leveldb:
 *   Copyright (c) 2011, The LevelDB Authors. All rights reserved.
 *   https://github.com/google/leveldb
 *
 * See LICENSE for more information.
 */

#ifndef LDB_STATUS_H
#define LDB_STATUS_H

#include <errno.h>
#include "extern.h"

/*
 * Constants
 */

#define LDB_OK             0
#define LDB_MINERR     30000
#define LDB_NOTFOUND   30001
#define LDB_CORRUPTION 30002
#define LDB_NOSUPPORT  30003
#define LDB_INVALID    30004
#define LDB_IOERR      30005
#define LDB_MAXERR     30005

#ifdef _WIN32
#  define LDB_ENOENT  2 /* ERROR_FILE_NOT_FOUND */
#  define LDB_ENOMEM  8 /* ERROR_NOT_ENOUGH_MEMORY */
#  define LDB_EINVAL 87 /* ERROR_INVALID_PARAMETER */
#  define LDB_EEXIST 80 /* ERROR_FILE_EXISTS */
#  define LDB_ENOLCK 33 /* ERROR_LOCK_VIOLATION */
#else
#  define LDB_ENOENT ENOENT
#  define LDB_ENOMEM ENOMEM
#  define LDB_EINVAL EINVAL
#  define LDB_EEXIST EEXIST
#  define LDB_ENOLCK ENOLCK
#endif

/*
 * Macros
 */

#define LDB_IS_STATUS(x) \
  ((x) == LDB_OK || ((x) >= LDB_MINERR && (x) <= LDB_MAXERR))

/*
 * Helpers
 */

LDB_EXTERN const char *
ldb_strerror(int code);

#endif /* LDB_STATUS_H */
