/*!
 * status.c - error codes for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on google/leveldb:
 *   Copyright (c) 2011, The LevelDB Authors. All rights reserved.
 *   https://github.com/google/leveldb
 *
 * See LICENSE for more information.
 */

#include "env.h"
#include "internal.h"
#include "status.h"

/*
 * Constants
 */

static const char *ldb_errmsg[] = {
  /* .LDB_OK = */ "OK",
  /* .LDB_NOTFOUND = */ "NotFound",
  /* .LDB_CORRUPTION = */ "Corruption",
  /* .LDB_NOSUPPORT = */ "Not implemented",
  /* .LDB_INVALID = */ "Invalid argument",
  /* .LDB_IOERR = */ "IO error"
};

/*
 * Status
 */

const char *
ldb_strerror(int code) {
  if (code == LDB_OK)
    return ldb_errmsg[LDB_OK];

  if (code >= LDB_MINERR && code <= LDB_MAXERR)
    return ldb_errmsg[code - LDB_MINERR];

  return ldb_error_string(code);
}
