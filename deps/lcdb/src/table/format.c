/*!
 * format.c - table format for lcdb
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
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "../util/buffer.h"
#include "../util/coding.h"
#include "../util/crc32c.h"
#include "../util/env.h"
#include "../util/internal.h"
#include "../util/options.h"
#include "../util/slice.h"
#include "../util/snappy.h"
#include "../util/status.h"

#include "format.h"

/*
 * BlockHandle
 */

void
ldb_handle_init(ldb_handle_t *x) {
  x->offset = ~UINT64_C(0);
  x->size = ~UINT64_C(0);
}

size_t
ldb_handle_size(const ldb_handle_t *x) {
  return ldb_varint64_size(x->offset) + ldb_varint64_size(x->size);
}

uint8_t *
ldb_handle_write(uint8_t *zp, const ldb_handle_t *x) {
  /* Sanity check that all fields have been set. */
  assert(x->offset != ~UINT64_C(0));
  assert(x->size != ~UINT64_C(0));

  zp = ldb_varint64_write(zp, x->offset);
  zp = ldb_varint64_write(zp, x->size);

  return zp;
}

void
ldb_handle_export(ldb_buffer_t *z, const ldb_handle_t *x) {
  uint8_t *zp = ldb_buffer_expand(z, LDB_HANDLE_SIZE);
  size_t xn = ldb_handle_write(zp, x) - zp;

  z->size += xn;
}

int
ldb_handle_read(ldb_handle_t *z, const uint8_t **xp, size_t *xn) {
  if (!ldb_varint64_read(&z->offset, xp, xn))
    return 0;

  if (!ldb_varint64_read(&z->size, xp, xn))
    return 0;

  return 1;
}

int
ldb_handle_import(ldb_handle_t *z, const ldb_slice_t *x) {
  ldb_slice_t tmp = *x;
  return ldb_handle_read(z, (const uint8_t **)&tmp.data, &tmp.size);
}

/*
 * Footer
 */

void
ldb_footer_init(ldb_footer_t *x) {
  ldb_handle_init(&x->metaindex_handle);
  ldb_handle_init(&x->index_handle);
}

uint8_t *
ldb_footer_write(uint8_t *zp, const ldb_footer_t *x) {
  uint8_t *tp = zp;
  size_t pad;

  zp = ldb_handle_write(zp, &x->metaindex_handle);
  zp = ldb_handle_write(zp, &x->index_handle);

  pad = (2 * LDB_HANDLE_SIZE) - (zp - tp);

  zp = ldb_padding_write(zp, pad);
  zp = ldb_fixed64_write(zp, LDB_TABLE_MAGIC);

  return zp;
}

void
ldb_footer_export(ldb_buffer_t *z, const ldb_footer_t *x) {
  uint8_t *zp = ldb_buffer_expand(z, LDB_FOOTER_SIZE);
  size_t xn = ldb_footer_write(zp, x) - zp;

  z->size += xn;
}

int
ldb_footer_read(ldb_footer_t *z, const uint8_t **xp, size_t *xn) {
  const uint8_t *tp = *xp;
  size_t tn = *xn;

  if (*xn < LDB_FOOTER_SIZE)
    return 0;

  if (ldb_fixed64_decode(*xp + LDB_FOOTER_SIZE - 8) != LDB_TABLE_MAGIC)
    return 0;

  if (!ldb_handle_read(&z->metaindex_handle, xp, xn))
    return 0;

  if (!ldb_handle_read(&z->index_handle, xp, xn))
    return 0;

  *xp = tp + LDB_FOOTER_SIZE;
  *xn = tn - LDB_FOOTER_SIZE;

  return 1;
}

int
ldb_footer_import(ldb_footer_t *z, const ldb_slice_t *x) {
  ldb_slice_t tmp = *x;
  return ldb_footer_read(z, (const uint8_t **)&tmp.data, &tmp.size);
}

/*
 * BlockContents
 */

void
ldb_contents_init(ldb_contents_t *x) {
  ldb_slice_init(&x->data);

  x->cachable = 0;
  x->heap_allocated = 0;
}

/*
 * ReadBlock
 */

int
ldb_read_block(ldb_contents_t *result,
               ldb_rfile_t *file,
               const ldb_readopt_t *options,
               const ldb_handle_t *handle) {
  ldb_slice_t contents;
  const uint8_t *data;
  uint8_t *buf = NULL;
  size_t n, len;
  int rc;

  ldb_contents_init(result);

  /* Check for overflow. */
  if (handle->size > SIZE_MAX - LDB_TRAILER_SIZE)
    return LDB_CORRUPTION;

  /* Read the block contents as well as the type/crc footer. */
  /* See table_builder.c for the code that built this structure. */
  n = handle->size;
  len = n + LDB_TRAILER_SIZE;

  if (!ldb_rfile_mapped(file)) {
    if ((buf = malloc(len)) == NULL)
      return LDB_ENOMEM;
  }

  rc = ldb_rfile_pread(file, &contents, buf, len, handle->offset);

  if (rc != LDB_OK) {
    ldb_free(buf);
    return rc;
  }

  if (contents.size != len) {
    ldb_free(buf);
    return LDB_IOERR; /* "truncated block read" */
  }

  /* Check the crc of the type and the block contents. */
  data = contents.data; /* Pointer to where Read put the data. */

  if (options->verify_checksums) {
    uint32_t crc = ldb_crc32c_unmask(ldb_fixed32_decode(data + n + 1));
    uint32_t actual = ldb_crc32c_value(data, n + 1);

    if (crc != actual) {
      ldb_free(buf);
      return LDB_CORRUPTION; /* "block checksum mismatch" */
    }
  }

  switch (data[n]) {
    case LDB_NO_COMPRESSION: {
      if (data != buf) {
        /* File implementation gave us pointer to some other data.
           Use it directly under the assumption that it will be live
           while the file is open. */
        ldb_free(buf);
        ldb_slice_set(&result->data, data, n);
        result->heap_allocated = 0;
        result->cachable = 0; /* Do not double-cache. */
      } else {
        ldb_slice_set(&result->data, buf, n);
        result->heap_allocated = 1;
        result->cachable = 1;
      }

      /* Ok. */
      break;
    }

    case LDB_SNAPPY_COMPRESSION: {
      size_t ulength;
      uint8_t *ubuf;

      if (!snappy_decode_size(&ulength, data, n)) {
        ldb_free(buf);
        return LDB_CORRUPTION; /* "corrupted compressed block contents" */
      }

      if ((ubuf = malloc(ulength)) == NULL) {
        ldb_free(buf);
        return LDB_ENOMEM;
      }

      if (!snappy_decode(ubuf, data, n)) {
        ldb_free(buf);
        ldb_free(ubuf);
        return LDB_CORRUPTION; /* "corrupted compressed block contents" */
      }

      ldb_free(buf);

      ldb_slice_set(&result->data, ubuf, ulength);

      result->heap_allocated = 1;
      result->cachable = 1;

      break;
    }

    default: {
      ldb_free(buf);
      return LDB_CORRUPTION; /* "bad block type" */
    }
  }

  return LDB_OK;
}
