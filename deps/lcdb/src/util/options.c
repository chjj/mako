/*!
 * options.c - options for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on google/leveldb:
 *   Copyright (c) 2011, The LevelDB Authors. All rights reserved.
 *   https://github.com/google/leveldb
 *
 * See LICENSE for more information.
 */

#include <stddef.h>
#include "comparator.h"
#include "options.h"

/*
 * DB Options
 */

static const ldb_dbopt_t db_options = {
  /* .comparator = */ NULL,
  /* .create_if_missing = */ 0,
  /* .error_if_exists = */ 0,
  /* .paranoid_checks = */ 0,
  /* .info_log = */ NULL,
  /* .write_buffer_size = */ 4 * 1024 * 1024,
  /* .max_open_files = */ 1000,
  /* .block_cache = */ NULL,
  /* .block_size = */ 4 * 1024,
  /* .block_restart_interval = */ 16,
  /* .max_file_size = */ 2 * 1024 * 1024,
  /* .compression = */ LDB_SNAPPY_COMPRESSION,
  /* .reuse_logs = */ 0,
  /* .filter_policy = */ NULL,
  /* .use_mmap = */ 1
};

/*
 * Read Options
 */

static const ldb_readopt_t read_options = {
  /* .verify_checksums = */ 0,
  /* .fill_cache = */ 1,
  /* .snapshot = */ NULL
};

/*
 * Write Options
 */

static const ldb_writeopt_t write_options = {
  /* .sync = */ 0
};

/*
 * Iterator Options
 */

static const ldb_readopt_t iter_options = {
  /* .verify_checksums = */ 0,
  /* .fill_cache = */ 0,
  /* .snapshot = */ NULL
};

/*
 * Globals
 */

#ifdef _WIN32
const ldb_dbopt_t *ldb_dbopt_import(void) { return &db_options; }
const ldb_readopt_t *ldb_readopt_import(void) { return &read_options; }
const ldb_writeopt_t *ldb_writeopt_import(void) { return &write_options; }
const ldb_readopt_t *ldb_iteropt_import(void) { return &iter_options; }
#else
const ldb_dbopt_t *ldb_dbopt_default = &db_options;
const ldb_readopt_t *ldb_readopt_default = &read_options;
const ldb_writeopt_t *ldb_writeopt_default = &write_options;
const ldb_readopt_t *ldb_iteropt_default = &iter_options;
#endif
