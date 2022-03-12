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

typedef struct ldb_logwriter_s {
  struct ldb_wfile_s *file;
  ldb_buffer_t *dst; /* For testing. */
  int block_offset; /* Current offset in block. */

  /* crc32c values for all supported record types. These are
     pre-computed to reduce the overhead of computing the crc of the
     record type stored in the header. */
  uint32_t type_crc[LDB_MAX_RECTYPE + 1];
} ldb_logwriter_t;

/*
 * LogWriter
 */

/* Create a writer that will append data to "*file".
 * "*file" must have initial length "dest_length".
 * "*file" must remain live while this Writer is in use.
 */
ldb_logwriter_t *
ldb_logwriter_create(struct ldb_wfile_s *file, uint64_t length);

void
ldb_logwriter_destroy(ldb_logwriter_t *lw);

void
ldb_logwriter_init(ldb_logwriter_t *lw,
                   struct ldb_wfile_s *file,
                   uint64_t length);

int
ldb_logwriter_add_record(ldb_logwriter_t *lw, const ldb_slice_t *slice);

#endif /* LDB_LOG_WRITER_H */
