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

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

#include "util/buffer.h"
#include "util/coding.h"
#include "util/crc32c.h"
#include "util/env.h"
#include "util/internal.h"
#include "util/slice.h"
#include "util/status.h"

#include "log_format.h"
#include "log_writer.h"

/*
 * LogWriter
 */

static void
init_type_crc(uint32_t *type_crc) {
  uint8_t i;

  for (i = 0; (int)i <= LDB_MAX_RECTYPE; i++)
    type_crc[i] = ldb_crc32c_value(&i, 1);
}

ldb_logwriter_t *
ldb_logwriter_create(ldb_wfile_t *file, uint64_t length) {
  ldb_logwriter_t *lw = ldb_malloc(sizeof(ldb_logwriter_t));
  ldb_logwriter_init(lw, file, length);
  return lw;
}

void
ldb_logwriter_destroy(ldb_logwriter_t *lw) {
  ldb_free(lw);
}

void
ldb_logwriter_init(ldb_logwriter_t *lw, ldb_wfile_t *file, uint64_t length) {
  lw->file = file;
  lw->dst = NULL; /* For testing. */
  lw->block_offset = length % LDB_BLOCK_SIZE;
  init_type_crc(lw->type_crc);
}

static int
emit_physical_record(ldb_logwriter_t *lw,
                     ldb_rectype_t type,
                     const uint8_t *ptr,
                     size_t length) {
  uint8_t buf[LDB_HEADER_SIZE];
  ldb_slice_t data;
  int rc = LDB_OK;
  uint32_t crc;

  assert(length <= 0xffff); /* Must fit in two bytes. */
  assert(lw->block_offset + LDB_HEADER_SIZE + length <= LDB_BLOCK_SIZE);

  /* Format the header. */
  buf[4] = (uint8_t)(length & 0xff);
  buf[5] = (uint8_t)(length >> 8);
  buf[6] = (uint8_t)(type);

  /* Compute the crc of the record type and the payload. */
  crc = ldb_crc32c_extend(lw->type_crc[type], ptr, length);
  crc = ldb_crc32c_mask(crc); /* Adjust for storage. */

  ldb_fixed32_write(buf, crc);

  if (lw->dst != NULL) {
    ldb_buffer_append(lw->dst, buf, LDB_HEADER_SIZE);
    ldb_buffer_append(lw->dst, ptr, length);
  } else {
    /* Write the header and the payload. */
    ldb_slice_set(&data, buf, LDB_HEADER_SIZE);

    rc = ldb_wfile_append(lw->file, &data);

    if (rc == LDB_OK) {
      ldb_slice_set(&data, ptr, length);

      rc = ldb_wfile_append(lw->file, &data);

      if (rc == LDB_OK)
        rc = ldb_wfile_flush(lw->file);
    }
  }

  lw->block_offset += LDB_HEADER_SIZE + length;

  return rc;
}

int
ldb_logwriter_add_record(ldb_logwriter_t *lw, const ldb_slice_t *slice) {
  static const uint8_t zeroes[LDB_HEADER_SIZE] = {0};
  const uint8_t *ptr = slice->data;
  size_t left = slice->size;
  int rc = LDB_OK;
  int begin = 1;

  /* Fragment the record if necessary and emit it.  Note that if slice
     is empty, we still want to iterate once to emit a single
     zero-length record. */
  do {
    int leftover = LDB_BLOCK_SIZE - lw->block_offset;
    size_t avail, fragment_length;
    ldb_rectype_t type;
    int end;

    assert(leftover >= 0);

    if (leftover < LDB_HEADER_SIZE) {
      /* Switch to a new block. */
      if (leftover > 0) {
        /* Fill the trailer. */
        ldb_slice_t padding;

        ldb_slice_set(&padding, zeroes, leftover);

        if (lw->dst != NULL)
          ldb_buffer_concat(lw->dst, &padding);
        else
          ldb_wfile_append(lw->file, &padding);
      }

      lw->block_offset = 0;
    }

    /* Invariant: we never leave < LDB_HEADER_SIZE bytes in a block. */
    assert(LDB_BLOCK_SIZE - lw->block_offset - LDB_HEADER_SIZE >= 0);

    avail = LDB_BLOCK_SIZE - lw->block_offset - LDB_HEADER_SIZE;
    fragment_length = (left < avail) ? left : avail;
    end = (left == fragment_length);

    if (begin && end) {
      type = LDB_TYPE_FULL;
    } else if (begin) {
      type = LDB_TYPE_FIRST;
    } else if (end) {
      type = LDB_TYPE_LAST;
    } else {
      type = LDB_TYPE_MIDDLE;
    }

    rc = emit_physical_record(lw, type, ptr, fragment_length);
    ptr += fragment_length;
    left -= fragment_length;
    begin = 0;
  } while (rc == LDB_OK && left > 0);

  return rc;
}
