/*!
 * version_edit.c - version edit for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on google/leveldb:
 *   Copyright (c) 2011, The LevelDB Authors. All rights reserved.
 *   https://github.com/google/leveldb
 *
 * See LICENSE for more information.
 */

#include <stdint.h>
#include <stdlib.h>

#include "util/buffer.h"
#include "util/coding.h"
#include "util/internal.h"
#include "util/rbt.h"
#include "util/slice.h"
#include "util/vector.h"

#include "dbformat.h"
#include "version_edit.h"

/*
 * Constants
 */

/* Tag numbers for serialized VersionEdit. These numbers are written to
   disk and should not be changed. */
enum {
  TAG_COMPARATOR = 1,
  TAG_LOG_NUMBER = 2,
  TAG_NEXT_FILE_NUMBER = 3,
  TAG_LAST_SEQUENCE = 4,
  TAG_COMPACT_POINTER = 5,
  TAG_DELETED_FILE = 6,
  TAG_NEW_FILE = 7,
  /* 8 was used for large value refs. */
  TAG_PREV_LOG_NUMBER = 9
};

/*
 * InternalKey Pair
 */

static ikey_entry_t *
ikey_entry_create(int level, const ldb_ikey_t *key) {
  ikey_entry_t *entry = ldb_malloc(sizeof(ikey_entry_t));

  entry->level = level;

  ldb_ikey_init(&entry->key);
  ldb_ikey_copy(&entry->key, key);

  return entry;
}

static void
ikey_entry_destroy(ikey_entry_t *entry) {
  ldb_ikey_clear(&entry->key);
  ldb_free(entry);
}

/*
 * FileNumber Pair
 */

static file_entry_t *
file_entry_create(int level, uint64_t number) {
  file_entry_t *entry = ldb_malloc(sizeof(file_entry_t));

  entry->level = level;
  entry->number = number;

  return entry;
}

static void
file_entry_destroy(file_entry_t *entry) {
  ldb_free(entry);
}

static int
file_entry_compare(rb_val_t x, rb_val_t y, void *arg) {
  file_entry_t *xp = x.p;
  file_entry_t *yp = y.p;

  (void)arg;

  if (xp->level != yp->level)
    return xp->level - yp->level;

  if (xp->number == yp->number)
    return 0;

  return xp->number < yp->number ? -1 : 1;
}

static void
file_entry_destruct(rb_node_t *node) {
  file_entry_destroy(node->key.p);
}

/*
 * FileMetaData Pair
 */

static meta_entry_t *
meta_entry_create(int level,
                  uint64_t number,
                  uint64_t file_size,
                  const ldb_ikey_t *smallest,
                  const ldb_ikey_t *largest) {
  meta_entry_t *entry = ldb_malloc(sizeof(meta_entry_t));

  entry->level = level;

  ldb_filemeta_init(&entry->meta);

  entry->meta.number = number;
  entry->meta.file_size = file_size;

  ldb_ikey_copy(&entry->meta.smallest, smallest);
  ldb_ikey_copy(&entry->meta.largest, largest);

  return entry;
}

static void
meta_entry_destroy(meta_entry_t *entry) {
  ldb_filemeta_clear(&entry->meta);
  ldb_free(entry);
}

/*
 * FileMetaData
 */

ldb_filemeta_t *
ldb_filemeta_create(void) {
  ldb_filemeta_t *meta = ldb_malloc(sizeof(ldb_filemeta_t));
  ldb_filemeta_init(meta);
  return meta;
}

void
ldb_filemeta_destroy(ldb_filemeta_t *meta) {
  ldb_filemeta_clear(meta);
  ldb_free(meta);
}

ldb_filemeta_t *
ldb_filemeta_clone(const ldb_filemeta_t *meta) {
  ldb_filemeta_t *out = ldb_filemeta_create();
  ldb_filemeta_copy(out, meta);
  return out;
}

void
ldb_filemeta_ref(ldb_filemeta_t *z) {
  z->refs++;
}

void
ldb_filemeta_unref(ldb_filemeta_t *z) {
  /* assert(z->refs > 0); */

  z->refs--;

  if (z->refs <= 0)
    ldb_filemeta_destroy(z);
}

void
ldb_filemeta_init(ldb_filemeta_t *meta) {
  meta->refs = 0;
  meta->allowed_seeks = (1 << 30);
  meta->number = 0;
  meta->file_size = 0;

  ldb_ikey_init(&meta->smallest);
  ldb_ikey_init(&meta->largest);
}

void
ldb_filemeta_clear(ldb_filemeta_t *meta) {
  ldb_ikey_clear(&meta->smallest);
  ldb_ikey_clear(&meta->largest);
}

void
ldb_filemeta_copy(ldb_filemeta_t *z, const ldb_filemeta_t *x) {
  z->refs = x->refs;
  z->allowed_seeks = x->allowed_seeks;
  z->number = x->number;
  z->file_size = x->file_size;

  ldb_ikey_copy(&z->smallest, &x->smallest);
  ldb_ikey_copy(&z->largest, &x->largest);
}

/*
 * VersionEdit
 */

void
ldb_vedit_init(ldb_vedit_t *edit) {
  ldb_buffer_init(&edit->comparator);

  edit->log_number = 0;
  edit->prev_log_number = 0;
  edit->last_sequence = 0;
  edit->next_file_number = 0;
  edit->has_comparator = 0;
  edit->has_log_number = 0;
  edit->has_prev_log_number = 0;
  edit->has_next_file_number = 0;
  edit->has_last_sequence = 0;

  ldb_vector_init(&edit->compact_pointers);
  rb_set_init(&edit->deleted_files, file_entry_compare, NULL);
  ldb_vector_init(&edit->new_files);
}

void
ldb_vedit_clear(ldb_vedit_t *edit) {
  size_t i;

  for (i = 0; i < edit->compact_pointers.length; i++)
    ikey_entry_destroy(edit->compact_pointers.items[i]);

  for (i = 0; i < edit->new_files.length; i++)
    meta_entry_destroy(edit->new_files.items[i]);

  ldb_buffer_clear(&edit->comparator);
  ldb_vector_clear(&edit->compact_pointers);
  rb_set_clear(&edit->deleted_files, file_entry_destruct);
  ldb_vector_clear(&edit->new_files);
}

void
ldb_vedit_reset(ldb_vedit_t *edit) {
  ldb_vedit_clear(edit);
  ldb_vedit_init(edit);
}

void
ldb_vedit_set_comparator_name(ldb_vedit_t *edit, const char *name) {
  edit->has_comparator = 1;
  ldb_buffer_set_str(&edit->comparator, name);
}

void
ldb_vedit_set_log_number(ldb_vedit_t *edit, uint64_t num) {
  edit->has_log_number = 1;
  edit->log_number = num;
}

void
ldb_vedit_set_prev_log_number(ldb_vedit_t *edit, uint64_t num) {
  edit->has_prev_log_number = 1;
  edit->prev_log_number = num;
}

void
ldb_vedit_set_next_file(ldb_vedit_t *edit, uint64_t num) {
  edit->has_next_file_number = 1;
  edit->next_file_number = num;
}

void
ldb_vedit_set_last_sequence(ldb_vedit_t *edit, ldb_seqnum_t seq) {
  edit->has_last_sequence = 1;
  edit->last_sequence = seq;
}

void
ldb_vedit_set_compact_pointer(ldb_vedit_t *edit,
                              int level,
                              const ldb_ikey_t *key) {
  ikey_entry_t *entry = ikey_entry_create(level, key);

  ldb_vector_push(&edit->compact_pointers, entry);
}

void
ldb_vedit_add_file(ldb_vedit_t *edit,
                   int level,
                   uint64_t number,
                   uint64_t file_size,
                   const ldb_ikey_t *smallest,
                   const ldb_ikey_t *largest) {
  meta_entry_t *entry = meta_entry_create(level,
                                          number,
                                          file_size,
                                          smallest,
                                          largest);

  ldb_vector_push(&edit->new_files, entry);
}

void
ldb_vedit_remove_file(ldb_vedit_t *edit, int level, uint64_t number) {
  file_entry_t *entry = file_entry_create(level, number);

  if (!rb_set_put(&edit->deleted_files, entry))
    file_entry_destroy(entry);
}

void
ldb_vedit_export(ldb_buffer_t *dst, const ldb_vedit_t *edit) {
  void *item;
  size_t i;

  if (edit->has_comparator) {
    ldb_buffer_varint32(dst, TAG_COMPARATOR);
    ldb_buffer_export(dst, &edit->comparator);
  }

  if (edit->has_log_number) {
    ldb_buffer_varint32(dst, TAG_LOG_NUMBER);
    ldb_buffer_varint64(dst, edit->log_number);
  }

  if (edit->has_prev_log_number) {
    ldb_buffer_varint32(dst, TAG_PREV_LOG_NUMBER);
    ldb_buffer_varint64(dst, edit->prev_log_number);
  }

  if (edit->has_next_file_number) {
    ldb_buffer_varint32(dst, TAG_NEXT_FILE_NUMBER);
    ldb_buffer_varint64(dst, edit->next_file_number);
  }

  if (edit->has_last_sequence) {
    ldb_buffer_varint32(dst, TAG_LAST_SEQUENCE);
    ldb_buffer_varint64(dst, edit->last_sequence);
  }

  for (i = 0; i < edit->compact_pointers.length; i++) {
    const ikey_entry_t *entry = edit->compact_pointers.items[i];
    const ldb_ikey_t *key = &entry->key;

    ldb_buffer_varint32(dst, TAG_COMPACT_POINTER);
    ldb_buffer_varint32(dst, entry->level);
    ldb_ikey_export(dst, key);
  }

  rb_set_iterate(&edit->deleted_files, item) {
    const file_entry_t *entry = item;

    ldb_buffer_varint32(dst, TAG_DELETED_FILE);
    ldb_buffer_varint32(dst, entry->level);
    ldb_buffer_varint64(dst, entry->number);
  }

  for (i = 0; i < edit->new_files.length; i++) {
    const meta_entry_t *entry = edit->new_files.items[i];
    const ldb_filemeta_t *meta = &entry->meta;

    ldb_buffer_varint32(dst, TAG_NEW_FILE);
    ldb_buffer_varint32(dst, entry->level);
    ldb_buffer_varint64(dst, meta->number);
    ldb_buffer_varint64(dst, meta->file_size);
    ldb_ikey_export(dst, &meta->smallest);
    ldb_ikey_export(dst, &meta->largest);
  }
}

static int
ldb_level_slurp(int *level, ldb_slice_t *input) {
  uint32_t val;

  if (!ldb_varint32_slurp(&val, input))
    return 0;

  if (val >= LDB_NUM_LEVELS)
    return 0;

  *level = val;

  return 1;
}

int
ldb_vedit_import(ldb_vedit_t *edit, const ldb_slice_t *src) {
  ldb_slice_t smallest, largest;
  uint64_t number, file_size;
  ldb_slice_t input = *src;
  ldb_slice_t key;
  uint32_t tag;
  int level;

  ldb_vedit_reset(edit);

  while (input.size > 0) {
    if (!ldb_varint32_slurp(&tag, &input))
      return 0;

    switch (tag) {
      case TAG_COMPARATOR: {
        if (!ldb_buffer_slurp(&edit->comparator, &input))
          return 0;

        edit->has_comparator = 1;

        break;
      }

      case TAG_LOG_NUMBER: {
        if (!ldb_varint64_slurp(&edit->log_number, &input))
          return 0;

        edit->has_log_number = 1;

        break;
      }

      case TAG_PREV_LOG_NUMBER: {
        if (!ldb_varint64_slurp(&edit->prev_log_number, &input))
          return 0;

        edit->has_prev_log_number = 1;

        break;
      }

      case TAG_NEXT_FILE_NUMBER: {
        if (!ldb_varint64_slurp(&edit->next_file_number, &input))
          return 0;

        edit->has_next_file_number = 1;

        break;
      }

      case TAG_LAST_SEQUENCE: {
        if (!ldb_varint64_slurp(&edit->last_sequence, &input))
          return 0;

        edit->has_last_sequence = 1;

        break;
      }

      case TAG_COMPACT_POINTER: {
        if (!ldb_level_slurp(&level, &input))
          return 0;

        if (!ldb_slice_slurp(&key, &input))
          return 0;

        if (key.size < 8)
          return 0;

        ldb_vedit_set_compact_pointer(edit, level, &key);

        break;
      }

      case TAG_DELETED_FILE: {
        if (!ldb_level_slurp(&level, &input))
          return 0;

        if (!ldb_varint64_slurp(&number, &input))
          return 0;

        ldb_vedit_remove_file(edit, level, number);

        break;
      }

      case TAG_NEW_FILE: {
        if (!ldb_level_slurp(&level, &input))
          return 0;

        if (!ldb_varint64_slurp(&number, &input))
          return 0;

        if (!ldb_varint64_slurp(&file_size, &input))
          return 0;

        if (!ldb_slice_slurp(&smallest, &input))
          return 0;

        if (!ldb_slice_slurp(&largest, &input))
          return 0;

        if (smallest.size < 8 || largest.size < 8)
          return 0;

        ldb_vedit_add_file(edit, level, number, file_size, &smallest, &largest);

        break;
      }

      default: {
        return 0;
      }
    }
  }

  return 1;
}

void
ldb_vedit_debug(ldb_buffer_t *z, const ldb_vedit_t *edit) {
  void *item;
  size_t i;

  ldb_buffer_string(z, "VersionEdit {");

  if (edit->has_comparator) {
    ldb_buffer_string(z, "\n  Comparator: ");
    ldb_buffer_concat(z, &edit->comparator);
  }

  if (edit->has_log_number) {
    ldb_buffer_string(z, "\n  LogNumber: ");
    ldb_buffer_number(z, edit->log_number);
  }

  if (edit->has_prev_log_number) {
    ldb_buffer_string(z, "\n  PrevLogNumber: ");
    ldb_buffer_number(z, edit->prev_log_number);
  }

  if (edit->has_next_file_number) {
    ldb_buffer_string(z, "\n  NextFile: ");
    ldb_buffer_number(z, edit->next_file_number);
  }

  if (edit->has_last_sequence) {
    ldb_buffer_string(z, "\n  LastSeq: ");
    ldb_buffer_number(z, edit->last_sequence);
  }

  for (i = 0; i < edit->compact_pointers.length; i++) {
    const ikey_entry_t *entry = edit->compact_pointers.items[i];

    ldb_buffer_string(z, "\n  CompactPointer: ");
    ldb_buffer_number(z, entry->level);
    ldb_buffer_string(z, " ");
    ldb_ikey_debug(z, &entry->key);
  }

  rb_set_iterate(&edit->deleted_files, item) {
    const file_entry_t *entry = item;

    ldb_buffer_string(z, "\n  RemoveFile: ");
    ldb_buffer_number(z, entry->level);
    ldb_buffer_string(z, " ");
    ldb_buffer_number(z, entry->number);
  }

  for (i = 0; i < edit->new_files.length; i++) {
    const meta_entry_t *entry = edit->new_files.items[i];
    const ldb_filemeta_t *f = &entry->meta;

    ldb_buffer_string(z, "\n  AddFile: ");
    ldb_buffer_number(z, entry->level);
    ldb_buffer_string(z, " ");
    ldb_buffer_number(z, f->number);
    ldb_buffer_string(z, " ");
    ldb_buffer_number(z, f->file_size);
    ldb_buffer_string(z, " ");
    ldb_ikey_debug(z, &f->smallest);
    ldb_buffer_string(z, " .. ");
    ldb_ikey_debug(z, &f->largest);
  }

  ldb_buffer_string(z, "\n}\n");
}
