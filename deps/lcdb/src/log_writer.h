/*!
 * log_writer.h - log writer for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on google/leveldb:
 *   Copyright (c) 2011, The LevelDB Authors. All rights reserved.
 *   https://github.com/google/leveldb
 *
 * See LICENSE for more information.
 */

#ifndef LDB_LOG_WRITER_H
#define LDB_LOG_WRITER_H

#include <stdint.h>

#include "util/types.h"
#include "log_format.h"

/*
 * Types
 */

struct ldb_wfile_s;

typedef struct ldb_writer_s {
  struct ldb_wfile_s *file;
  ldb_buffer_t *dst; /* For testing. */
  int block_offset; /* Current offset in block. */

  /* crc32c values for all supported record types. These are
     pre-computed to reduce the overhead of computing the crc of the
     record type stored in the header. */
  uint32_t type_crc[LDB_MAX_RECTYPE + 1];
} ldb_writer_t;

/*
 * LogWriter
 */

/* Create a writer that will append data to "*file".
 * "*file" must have initial length "dest_length".
 * "*file" must remain live while this Writer is in use.
 */
ldb_writer_t *
ldb_writer_create(struct ldb_wfile_s *file, uint64_t length);

void
ldb_writer_destroy(ldb_writer_t *lw);

void
ldb_writer_init(ldb_writer_t *lw,
                struct ldb_wfile_s *file,
                uint64_t length);

int
ldb_writer_add_record(ldb_writer_t *lw, const ldb_slice_t *slice);

#endif /* LDB_LOG_WRITER_H */
