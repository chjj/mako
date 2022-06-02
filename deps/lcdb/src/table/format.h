/*!
 * format.h - table format for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on google/leveldb:
 *   Copyright (c) 2011, The LevelDB Authors. All rights reserved.
 *   https://github.com/google/leveldb
 *
 * See LICENSE for more information.
 */

#ifndef LDB_TABLE_FORMAT_H
#define LDB_TABLE_FORMAT_H

#include <stddef.h>
#include <stdint.h>

#include "../util/types.h"

/*
 * Constants
 */

/* Maximum encoding length of a BlockHandle. */
#define LDB_BLOCKHANDLE_MAX (10 + 10) /* kMaxEncodedLength */

/* Encoded length of a Footer. Note that the serialization of a
   Footer will always occupy exactly this many bytes. It consists
   of two block handles and a magic number. */
#define LDB_FOOTER_SIZE (2 * LDB_BLOCKHANDLE_MAX + 8) /* kEncodedLength */

/* 1-byte type + 32-bit crc. */
#define LDB_BLOCK_TRAILER_SIZE 5 /* kBlockTrailerSize */

/* kTableMagicNumber was picked by running
      echo http://code.google.com/p/leveldb/ | sha1sum
   and taking the leading 64 bits. */
#define LDB_TABLE_MAGIC UINT64_C(0xdb4775248b80fb57) /* kTableMagicNumber */

/*
 * Types
 */

struct ldb_rfile_s;
struct ldb_readopt_s;

/* BlockHandle is a pointer to the extent of a file that stores a data
   block or a meta block. */
typedef struct ldb_handle_s {
  uint64_t offset;
  uint64_t size;
} ldb_handle_t;

/* Footer encapsulates the fixed information stored at the tail
   end of every table file. */
typedef struct ldb_footer_s {
  ldb_handle_t metaindex_handle;
  ldb_handle_t index_handle;
} ldb_footer_t;

typedef struct ldb_contents_s {
  ldb_slice_t data;    /* Actual contents of data. */
  int cachable;        /* True iff data can be cached. */
  int heap_allocated;  /* True iff caller should free() data.data. */
} ldb_contents_t;

/*
 * BlockHandle
 */

void
ldb_handle_init(ldb_handle_t *x);

size_t
ldb_handle_size(const ldb_handle_t *x);

uint8_t *
ldb_handle_write(uint8_t *zp, const ldb_handle_t *x);

void
ldb_handle_export(ldb_buffer_t *z, const ldb_handle_t *x);

int
ldb_handle_read(ldb_handle_t *z, const uint8_t **xp, size_t *xn);

int
ldb_handle_import(ldb_handle_t *z, const ldb_slice_t *x);

/*
 * Footer
 */

void
ldb_footer_init(ldb_footer_t *x);

uint8_t *
ldb_footer_write(uint8_t *zp, const ldb_footer_t *x);

void
ldb_footer_export(ldb_buffer_t *z, const ldb_footer_t *x);

int
ldb_footer_read(ldb_footer_t *z, const uint8_t **xp, size_t *xn);

int
ldb_footer_import(ldb_footer_t *z, const ldb_slice_t *x);

/*
 * BlockContents
 */

void
ldb_contents_init(ldb_contents_t *x);

/*
 * Block Read
 */

int
ldb_read_block(ldb_contents_t *result,
               struct ldb_rfile_s *file,
               const struct ldb_readopt_s *options,
               const ldb_handle_t *handle);

#endif /* LDB_TABLE_FORMAT_H */
