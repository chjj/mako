/*!
 * log_reader.h - log reader for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on google/leveldb:
 *   Copyright (c) 2011, The LevelDB Authors. All rights reserved.
 *   https://github.com/google/leveldb
 *
 * See LICENSE for more information.
 */

#ifndef LDB_LOG_READER_H
#define LDB_LOG_READER_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "util/types.h"

/*
 * Types
 */

struct ldb_logger_s;
struct ldb_rfile_s;

/* Interface for reporting errors. */
typedef struct ldb_reporter_s {
  const char *fname; /* db_impl.c */
  int *status; /* db_impl.c, version_set.c, t-log.c */
  struct ldb_logger_s *info_log; /* db_impl.c, repair.c */
  uint64_t lognum; /* repair.c */
  FILE *dst; /* dumpfile.c */
  size_t dropped_bytes; /* t-log.c */
  /* Some corruption was detected. "bytes" is the approximate number
     of bytes dropped due to the corruption. */
  void (*corruption)(struct ldb_reporter_s *reporter, size_t bytes, int status);
} ldb_reporter_t;

typedef struct ldb_reader_s {
  struct ldb_rfile_s *file; /* SequentialFile */
  ldb_slice_t *src; /* For testing. */
  int error; /* For testing. */
  ldb_reporter_t *reporter;
  int checksum;
  uint8_t *backing_store;
  ldb_slice_t buffer;
  int eof; /* Last read() indicated EOF by returning < LDB_BLOCK_SIZE. */

  /* Offset of the last record returned by read_record. */
  uint64_t last_offset;

  /* Offset of the first location past the end of buffer. */
  uint64_t end_offset;

  /* Offset at which to start looking for the first record to return. */
  uint64_t initial_offset;

  /* True if we are resynchronizing after a seek (initial_offset > 0). In
     particular, a run of LDB_TYPE_MIDDLE and LDB_TYPE_LAST records can
     be silently skipped in this mode. */
  int resyncing;
} ldb_reader_t;

/*
 * LogReader
 */

/* Create a reader that will return log records from "*file".
 * "*file" must remain live while this Reader is in use.
 *
 * If "reporter" is non-null, it is notified whenever some data is
 * dropped due to a detected corruption. "*reporter" must remain
 * live while this Reader is in use.
 *
 * If "checksum" is true, verify checksums if available.
 *
 * The Reader will start reading at the first record located at physical
 * position >= initial_offset within the file.
 */
void
ldb_reader_init(ldb_reader_t *lr,
                struct ldb_rfile_s *file,
                ldb_reporter_t *reporter,
                int checksum,
                uint64_t initial_offset);

void
ldb_reader_clear(ldb_reader_t *lr);

/* Read the next record into *record. Returns true if read
 * successfully, false if we hit end of the input. May use
 * "*scratch" as temporary storage. The contents filled in *record
 * will only be valid until the next mutating operation on this
 * reader or the next mutation to *scratch.
 */
int
ldb_reader_read_record(ldb_reader_t *lr,
                       ldb_slice_t *record,
                       ldb_buffer_t *scratch);

#endif /* LDB_LOG_READER_H */
