/*!
 * env.c - platform-specific functions for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on google/leveldb:
 *   Copyright (c) 2011, The LevelDB Authors. All rights reserved.
 *   https://github.com/google/leveldb
 *
 * See LICENSE for more information.
 */

#if defined(LDB_MEMENV)
#  include "env_mem_impl.h"
#elif defined(_WIN32)
#  include "env_win_impl.h"
#else
#  include "env_unix_impl.h"
#endif

#include "buffer.h"
#include "strutil.h"

int
ldb_write_file(const char *fname, const ldb_slice_t *data, int should_sync) {
  ldb_wfile_t *file;
  int rc;

  if ((rc = ldb_truncfile_create(fname, &file)))
    return rc;

  rc = ldb_wfile_append(file, data);

  if (rc == LDB_OK && should_sync)
    rc = ldb_wfile_sync(file);

  if (rc == LDB_OK)
    rc = ldb_wfile_close(file);

  ldb_wfile_destroy(file);

  if (rc != LDB_OK)
    ldb_remove_file(fname);

  return rc;
}

int
ldb_read_file(const char *fname, ldb_buffer_t *data) {
  ldb_rfile_t *file;
  ldb_slice_t chunk;
  char space[8192];
  int rc;

  if ((rc = ldb_seqfile_create(fname, &file)))
    return rc;

  ldb_buffer_reset(data);

  for (;;) {
    rc = ldb_rfile_read(file, &chunk, space, sizeof(space));

    if (rc != LDB_OK)
      break;

    if (chunk.size == 0)
      break;

    ldb_buffer_append(data, chunk.data, chunk.size);
  }

  ldb_rfile_destroy(file);

  return rc;
}

int
ldb_test_filename(char *result, size_t size, const char *name) {
  if (!ldb_test_directory(result, size))
    return 0;

  return ldb_join(result, size, result, name);
}
