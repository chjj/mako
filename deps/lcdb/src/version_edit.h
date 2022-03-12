/*!
 * version_edit.h - version edit for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on google/leveldb:
 *   Copyright (c) 2011, The LevelDB Authors. All rights reserved.
 *   https://github.com/google/leveldb
 *
 * See LICENSE for more information.
 */

#ifndef LDB_VERSION_EDIT_H
#define LDB_VERSION_EDIT_H

#include <stddef.h>
#include <stdint.h>

#include "util/rbt.h"
#include "util/types.h"

#include "dbformat.h"

/*
 * Types
 */

typedef struct ldb_filemeta_s {
  int refs;
  int allowed_seeks;   /* Seeks allowed until compaction. */
  uint64_t number;
  uint64_t file_size;  /* File size in bytes. */
  ldb_ikey_t smallest; /* Smallest internal key served by table. */
  ldb_ikey_t largest;  /* Largest internal key served by table. */
} ldb_filemeta_t;

typedef struct ldb_vedit_s {
  ldb_buffer_t comparator;
  uint64_t log_number;
  uint64_t prev_log_number;
  uint64_t next_file_number;
  ldb_seqnum_t last_sequence;
  int has_comparator;
  int has_log_number;
  int has_prev_log_number;
  int has_next_file_number;
  int has_last_sequence;
  ldb_vector_t compact_pointers; /* ikey_entry_t */
  rb_set_t deleted_files;        /* file_entry_t */
  ldb_vector_t new_files;        /* meta_entry_t */
} ldb_vedit_t;

typedef struct ikey_entry_s {
  int level;
  ldb_ikey_t key;
} ikey_entry_t;

typedef struct file_entry_s {
  int level;
  uint64_t number;
} file_entry_t;

typedef struct meta_entry_s {
  int level;
  ldb_filemeta_t meta;
} meta_entry_t;

/*
 * FileMetaData
 */

ldb_filemeta_t *
ldb_filemeta_create(void);

void
ldb_filemeta_destroy(ldb_filemeta_t *meta);

ldb_filemeta_t *
ldb_filemeta_clone(const ldb_filemeta_t *meta);

void
ldb_filemeta_ref(ldb_filemeta_t *z);

void
ldb_filemeta_unref(ldb_filemeta_t *z);

void
ldb_filemeta_init(ldb_filemeta_t *meta);

void
ldb_filemeta_clear(ldb_filemeta_t *meta);

void
ldb_filemeta_copy(ldb_filemeta_t *z, const ldb_filemeta_t *x);

/*
 * VersionEdit
 */

void
ldb_vedit_init(ldb_vedit_t *edit);

void
ldb_vedit_clear(ldb_vedit_t *edit);

void
ldb_vedit_reset(ldb_vedit_t *edit);

void
ldb_vedit_set_comparator_name(ldb_vedit_t *edit, const char *name);

void
ldb_vedit_set_log_number(ldb_vedit_t *edit, uint64_t num);

void
ldb_vedit_set_prev_log_number(ldb_vedit_t *edit, uint64_t num);

void
ldb_vedit_set_next_file(ldb_vedit_t *edit, uint64_t num);

void
ldb_vedit_set_last_sequence(ldb_vedit_t *edit, ldb_seqnum_t seq);

void
ldb_vedit_set_compact_pointer(ldb_vedit_t *edit,
                              int level,
                              const ldb_ikey_t *key);

/* Add the specified file at the specified number. */
/* REQUIRES: This version has not been saved (see vset_save_to). */
/* REQUIRES: "smallest" and "largest" are smallest and largest keys in file. */
void
ldb_vedit_add_file(ldb_vedit_t *edit,
                   int level,
                   uint64_t number,
                   uint64_t file_size,
                   const ldb_ikey_t *smallest,
                   const ldb_ikey_t *largest);

/* Delete the specified "file" from the specified "level". */
void
ldb_vedit_remove_file(ldb_vedit_t *edit, int level, uint64_t number);

void
ldb_vedit_export(ldb_buffer_t *dst, const ldb_vedit_t *edit);

int
ldb_vedit_import(ldb_vedit_t *edit, const ldb_slice_t *src);

void
ldb_vedit_debug(ldb_buffer_t *z, const ldb_vedit_t *edit);

#endif /* LDB_VERSION_EDIT_H */
