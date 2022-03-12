/*!
 * filename.h - filename utilities for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on google/leveldb:
 *   Copyright (c) 2011, The LevelDB Authors. All rights reserved.
 *   https://github.com/google/leveldb
 *
 * See LICENSE for more information.
 */

#ifndef LDB_FILENAME_H
#define LDB_FILENAME_H

#include <stddef.h>
#include <stdint.h>

/*
 * Constants
 */

typedef enum ldb_filetype {
  LDB_FILE_LOG,
  LDB_FILE_LOCK,
  LDB_FILE_TABLE,
  LDB_FILE_DESC,
  LDB_FILE_CURRENT,
  LDB_FILE_TEMP,
  LDB_FILE_INFO /* Either the current one, or an old one */
} ldb_filetype_t;

/*
 * Filename
 */

/* Return the name of the log file with the specified number
   in the db named by "prefix". The result will be prefixed with
   "prefix". */
int
ldb_log_filename(char *buf, size_t size, const char *prefix, uint64_t num);

/* Return the name of the sstable with the specified number
   in the db named by "prefix". The result will be prefixed with
   "prefix". */
int
ldb_table_filename(char *buf, size_t size, const char *prefix, uint64_t num);

/* Return the legacy file name for an sstable with the specified number
   in the db named by "prefix". The result will be prefixed with
   "prefix". */
int
ldb_sstable_filename(char *buf, size_t size, const char *prefix, uint64_t num);

/* Return the name of the descriptor file for the db named by
   "prefix" and the specified incarnation number. The result will be
   prefixed with "prefix". */
int
ldb_desc_filename(char *buf, size_t size, const char *prefix, uint64_t num);

/* Return the name of the current file. This file contains the name
   of the current manifest file. The result will be prefixed with
   "prefix". */
int
ldb_current_filename(char *buf, size_t size, const char *prefix);

/* Return the name of the lock file for the db named by
   "prefix". The result will be prefixed with "prefix". */
int
ldb_lock_filename(char *buf, size_t size, const char *prefix);

/* Return the name of a temporary file owned by the db named "prefix".
   The result will be prefixed with "prefix". */
int
ldb_temp_filename(char *buf, size_t size, const char *prefix, uint64_t num);

/* Return the name of the info log file for "prefix". */
int
ldb_info_filename(char *buf, size_t size, const char *prefix);

/* Return the name of the old info log file for "prefix". */
int
ldb_oldinfo_filename(char *buf, size_t size, const char *prefix);

/* If filename is a leveldb file, store the type of the file in *type.
   The number encoded in the filename is stored in *num. If the
   filename was successfully parsed, returns true. Else return false. */
int
ldb_parse_filename(ldb_filetype_t *type, uint64_t *num, const char *name);

/* Make the CURRENT file point to the descriptor file with the
   specified number. */
int
ldb_set_current_file(const char *prefix, uint64_t desc_number);

#endif /* LDB_FILENAME_H */
