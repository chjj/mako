/*!
 * builder.c - table building function for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on google/leveldb:
 *   Copyright (c) 2011, The LevelDB Authors. All rights reserved.
 *   https://github.com/google/leveldb
 *
 * See LICENSE for more information.
 */

#include <assert.h>
#include <stdlib.h>

#include "table/iterator.h"
#include "table/table_builder.h"

#include "util/env.h"
#include "util/internal.h"
#include "util/options.h"
#include "util/status.h"

#include "builder.h"
#include "dbformat.h"
#include "filename.h"
#include "table_cache.h"
#include "version_edit.h"

/*
 * BuildTable
 */

int
ldb_build_table(const char *prefix,
                const ldb_dbopt_t *options,
                ldb_tcache_t *table_cache,
                ldb_iter_t *iter,
                ldb_filemeta_t *meta) {
  char fname[LDB_PATH_MAX];
  int rc = LDB_OK;

  meta->file_size = 0;

  ldb_iter_first(iter);

  if (!ldb_table_filename(fname, sizeof(fname), prefix, meta->number))
    return LDB_INVALID;

  if (ldb_iter_valid(iter)) {
    ldb_tablebuilder_t *builder;
    ldb_slice_t key, val;
    ldb_wfile_t *file;
    ldb_iter_t *it;

    rc = ldb_truncfile_create(fname, &file);

    if (rc != LDB_OK)
      return rc;

    builder = ldb_tablebuilder_create(options, file);

    key = ldb_iter_key(iter);

    ldb_ikey_copy(&meta->smallest, &key);

    ldb_slice_reset(&key);

    for (; ldb_iter_valid(iter); ldb_iter_next(iter)) {
      key = ldb_iter_key(iter);
      val = ldb_iter_value(iter);

      ldb_tablebuilder_add(builder, &key, &val);
    }

    if (key.size > 0)
      ldb_ikey_copy(&meta->largest, &key);

    /* Finish and check for builder errors. */
    rc = ldb_tablebuilder_finish(builder);

    if (rc == LDB_OK) {
      meta->file_size = ldb_tablebuilder_file_size(builder);

      assert(meta->file_size > 0);
    }

    ldb_tablebuilder_destroy(builder);

    /* Finish and check for file errors. */
    if (rc == LDB_OK)
      rc = ldb_wfile_sync(file);

    if (rc == LDB_OK)
      rc = ldb_wfile_close(file);

    ldb_wfile_destroy(file);
    file = NULL;

    if (rc == LDB_OK) {
      /* Verify that the table is usable. */
      it = ldb_tcache_iterate(table_cache,
                              ldb_readopt_default,
                              meta->number,
                              meta->file_size,
                              NULL);

      rc = ldb_iter_status(it);

      ldb_iter_destroy(it);
    }
  }

  /* Check for input iterator errors. */
  if (ldb_iter_status(iter) != LDB_OK)
    rc = ldb_iter_status(iter);

  if (rc == LDB_OK && meta->file_size > 0)
    ; /* Keep it. */
  else
    ldb_remove_file(fname);

  return rc;
}
