/*!
 * dumpfile.c - file dumps for lcdb
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "table/iterator.h"
#include "table/table.h"

#include "util/buffer.h"
#include "util/env.h"
#include "util/internal.h"
#include "util/options.h"
#include "util/slice.h"
#include "util/status.h"
#include "util/strutil.h"

#include "dbformat.h"
#include "dumpfile.h"
#include "filename.h"
#include "log_reader.h"
#include "version_edit.h"
#include "write_batch.h"

/*
 * Helpers
 */

static void
stream_append(FILE *stream, const ldb_slice_t *x) {
  fwrite(x->data, 1, x->size, stream);
}

static int
guess_type(const char *fname, ldb_filetype_t *type) {
  const char *base = ldb_basename(fname);
  uint64_t ignored;

  return ldb_parse_filename(type, &ignored, base);
}

/*
 * DumpFile
 */

/* Notified when log reader encounters corruption. */
static void
report_corruption(ldb_reporter_t *report, size_t bytes, int status) {
  ldb_buffer_t r;

  ldb_buffer_init(&r);
  ldb_buffer_string(&r, "corruption: ");
  ldb_buffer_number(&r, bytes);

  ldb_buffer_string(&r, " bytes; ");
  ldb_buffer_string(&r, ldb_strerror(status));
  ldb_buffer_push(&r, '\n');

  stream_append(report->dst, &r);
  ldb_buffer_clear(&r);
}

/* Print contents of a log file. (*func)() is called on every record. */
static int
print_log_contents(const char *fname,
                   void (*func)(uint64_t, const ldb_slice_t *, FILE *),
                   FILE *dst) {
  ldb_reporter_t reporter;
  ldb_logreader_t reader;
  ldb_buffer_t scratch;
  ldb_slice_t record;
  ldb_rfile_t *file;
  int rc;

  rc = ldb_seqfile_create(fname, &file);

  if (rc != LDB_OK)
    return rc;

  reporter.dst = dst;
  reporter.corruption = report_corruption;

  ldb_logreader_init(&reader, file, &reporter, 1, 0);
  ldb_buffer_init(&scratch);

  while (ldb_logreader_read_record(&reader, &record, &scratch))
    func(reader.last_offset, &record, dst);

  ldb_buffer_clear(&scratch);
  ldb_logreader_clear(&reader);
  ldb_rfile_destroy(file);

  return LDB_OK;
}

/* Called on every item found in a WriteBatch. */
static void
handle_put(ldb_handler_t *h, const ldb_slice_t *key, const ldb_slice_t *value) {
  FILE *dst = h->state;
  ldb_buffer_t r;

  ldb_buffer_init(&r);
  ldb_buffer_string(&r, "  put '");
  ldb_buffer_escape(&r, key);
  ldb_buffer_string(&r, "' '");
  ldb_buffer_escape(&r, value);
  ldb_buffer_string(&r, "'\n");

  stream_append(dst, &r);
  ldb_buffer_clear(&r);
}

static void
handle_del(ldb_handler_t *h, const ldb_slice_t *key) {
  FILE *dst = h->state;
  ldb_buffer_t r;

  ldb_buffer_init(&r);
  ldb_buffer_string(&r, "  del '");
  ldb_buffer_escape(&r, key);
  ldb_buffer_string(&r, "'\n");

  stream_append(dst, &r);
  ldb_buffer_clear(&r);
}

/* Called on every log record (each one of which is a WriteBatch)
   found in a LDB_FILE_LOG. */
static void
write_batch_printer(uint64_t pos, const ldb_slice_t *record, FILE *dst) {
  ldb_handler_t printer;
  ldb_batch_t batch;
  ldb_buffer_t r;
  int rc;

  ldb_buffer_init(&r);
  ldb_buffer_string(&r, "--- offset ");
  ldb_buffer_number(&r, pos);
  ldb_buffer_string(&r, "; ");

  if (record->size < 12) {
    ldb_buffer_string(&r, "log record length ");
    ldb_buffer_number(&r, record->size);
    ldb_buffer_string(&r, " is too small\n");
    stream_append(dst, &r);
    ldb_buffer_clear(&r);
    return;
  }

  ldb_batch_init(&batch);
  ldb_batch_set_contents(&batch, record);

  ldb_buffer_string(&r, "sequence ");
  ldb_buffer_number(&r, ldb_batch_sequence(&batch));
  ldb_buffer_push(&r, '\n');

  stream_append(dst, &r);

  printer.state = dst;
  printer.put = handle_put;
  printer.del = handle_del;

  rc = ldb_batch_iterate(&batch, &printer);

  if (rc != LDB_OK) {
    ldb_buffer_reset(&r);
    ldb_buffer_string(&r, "  error: ");
    ldb_buffer_string(&r, ldb_strerror(rc));
    ldb_buffer_push(&r, '\n');
    stream_append(dst, &r);
  }

  ldb_buffer_clear(&r);
  ldb_batch_clear(&batch);
}

static int
dump_log(const char *fname, FILE *dst) {
  return print_log_contents(fname, write_batch_printer, dst);
}

/* Called on every log record (each one of which is a WriteBatch)
   found in a LDB_FILE_DESC. */
static void
edit_printer(uint64_t pos, const ldb_slice_t *record, FILE *dst) {
  ldb_vedit_t edit;
  ldb_buffer_t r;

  ldb_vedit_init(&edit);

  ldb_buffer_init(&r);
  ldb_buffer_string(&r, "--- offset ");
  ldb_buffer_number(&r, pos);
  ldb_buffer_string(&r, "; ");

  if (!ldb_vedit_import(&edit, record)) {
    ldb_buffer_string(&r, ldb_strerror(LDB_CORRUPTION));
    ldb_buffer_push(&r, '\n');
  } else {
    ldb_vedit_debug(&r, &edit);
  }

  stream_append(dst, &r);

  ldb_buffer_clear(&r);
  ldb_vedit_clear(&edit);
}

static int
dump_descriptor(const char *fname, FILE *dst) {
  return print_log_contents(fname, edit_printer, dst);
}

static int
dump_table(const char *fname, FILE *dst) {
  ldb_readopt_t ro = *ldb_readopt_default;
  ldb_rfile_t *file = NULL;
  ldb_table_t *table = NULL;
  uint64_t file_size = 0;
  ldb_iter_t *iter;
  ldb_buffer_t r;
  int rc;

  rc = ldb_file_size(fname, &file_size);

  if (rc == LDB_OK)
    rc = ldb_randfile_create(fname, &file, 1);

  if (rc == LDB_OK) {
    /* We use the default comparator, which may or may not match the
       comparator used in this database. However this should not cause
       problems since we only use Table operations that do not require
       any comparisons. In particular, we do not call Seek or Prev. */
    rc = ldb_table_open(ldb_dbopt_default, file, file_size, &table);
  }

  if (rc != LDB_OK) {
    if (table != NULL)
      ldb_table_destroy(table);

    if (file != NULL)
      ldb_rfile_destroy(file);

    return rc;
  }

  ro.fill_cache = 0;

  iter = ldb_tableiter_create(table, &ro);

  ldb_buffer_init(&r);

  for (ldb_iter_first(iter); ldb_iter_valid(iter); ldb_iter_next(iter)) {
    ldb_slice_t key = ldb_iter_key(iter);
    ldb_slice_t val = ldb_iter_value(iter);
    ldb_pkey_t pkey;

    ldb_buffer_reset(&r);

    if (!ldb_pkey_import(&pkey, &key)) {
      ldb_buffer_string(&r, "badkey '");
      ldb_buffer_escape(&r, &key);
      ldb_buffer_string(&r, "' => '");
      ldb_buffer_escape(&r, &val);
      ldb_buffer_string(&r, "'\n");
      stream_append(dst, &r);
    } else {
      ldb_buffer_push(&r, '\'');
      ldb_buffer_escape(&r, &pkey.user_key);
      ldb_buffer_string(&r, "' @ ");
      ldb_buffer_number(&r, pkey.sequence);
      ldb_buffer_string(&r, " : ");

      if (pkey.type == LDB_TYPE_DELETION)
        ldb_buffer_string(&r, "del");
      else if (pkey.type == LDB_TYPE_VALUE)
        ldb_buffer_string(&r, "val");
      else
        ldb_buffer_number(&r, pkey.type);

      ldb_buffer_string(&r, " => '");
      ldb_buffer_escape(&r, &val);
      ldb_buffer_string(&r, "'\n");

      stream_append(dst, &r);
    }
  }

  rc = ldb_iter_status(iter);

  if (rc != LDB_OK) {
    ldb_buffer_reset(&r);
    ldb_buffer_string(&r, "iterator error: ");
    ldb_buffer_string(&r, ldb_strerror(rc));
    ldb_buffer_push(&r, '\n');

    stream_append(dst, &r);
  }

  ldb_buffer_clear(&r);

  ldb_iter_destroy(iter);
  ldb_table_destroy(table);
  ldb_rfile_destroy(file);

  return LDB_OK;
}

int
ldb_dump_file(const char *fname, FILE *dst) {
  ldb_filetype_t type;

  if (!guess_type(fname, &type))
    return LDB_INVALID; /* "[fname]: unknown file type" */

  switch (type) {
    case LDB_FILE_LOG:
      return dump_log(fname, dst);
    case LDB_FILE_DESC:
      return dump_descriptor(fname, dst);
    case LDB_FILE_TABLE:
      return dump_table(fname, dst);
    default:
      break;
  }

  return LDB_INVALID; /* "[fname]: not a dump-able file type" */
}
