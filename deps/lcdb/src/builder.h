/*!
 * builder.h - table building function for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on google/leveldb:
 *   Copyright (c) 2011, The LevelDB Authors. All rights reserved.
 *   https://github.com/google/leveldb
 *
 * See LICENSE for more information.
 */

#ifndef LDB_BUILDER_H
#define LDB_BUILDER_H

/*
 * Types
 */

struct ldb_dbopt_s;
struct ldb_filemeta_s;
struct ldb_iter_s;
struct ldb_tables_s;

/*
 * BuildTable
 */

/* Build a Table file from the contents of *iter. The generated file
   will be named according to meta->number. On success, the rest of
   *meta will be filled with metadata about the generated table.
   If no data is present in *iter, meta->file_size will be set to
   zero, and no Table file will be produced. */
int
ldb_build_table(const char *dbname,
                const struct ldb_dbopt_s *options,
                struct ldb_tables_s *table_cache,
                struct ldb_iter_s *iter,
                struct ldb_filemeta_s *meta);

#endif /* LDB_BUILDER_H */
