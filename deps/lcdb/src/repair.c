/*!
 * repair.c - database repairing for lcdb
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
#include <string.h>

#include "table/iterator.h"
#include "table/table.h"
#include "table/table_builder.h"

#include "util/array.h"
#include "util/bloom.h"
#include "util/buffer.h"
#include "util/cache.h"
#include "util/comparator.h"
#include "util/crc32c.h"
#include "util/env.h"
#include "util/internal.h"
#include "util/options.h"
#include "util/slice.h"
#include "util/status.h"
#include "util/strutil.h"
#include "util/vector.h"

#include "builder.h"
#include "db_impl.h"
#include "dbformat.h"
#include "filename.h"
#include "log_format.h"
#include "log_reader.h"
#include "log_writer.h"
#include "memtable.h"
#include "table_cache.h"
#include "version_edit.h"
#include "write_batch.h"

/* We recover the contents of the descriptor from the other files we find.
 *
 * (1) Any log files are first converted to tables
 *
 * (2) We scan every table to compute
 *     (a) smallest/largest for the table
 *     (b) largest sequence number in the table
 *
 * (3) We generate descriptor contents:
 *      - log number is set to zero
 *      - next-file-number is set to 1 + largest file number we found
 *      - last-sequence-number is set to largest sequence# found across
 *        all tables (see 2c)
 *      - compaction pointers are cleared
 *      - every table file is added at level 0
 *
 * Possible optimization 1:
 *   (a) Compute total size and use to pick appropriate max-level M
 *   (b) Sort tables by largest sequence# in the table
 *   (c) For each table: if it overlaps earlier table, place in level-0,
 *       else place in level-M.
 *
 * Possible optimization 2:
 *   Store per-table metadata (smallest, largest, largest-seq#, ...)
 *   in the table's meta section to speed up scan_table.
 */

/*
 * TableInfo
 */

typedef struct ldb_tabinfo_s {
  ldb_filemeta_t meta;
  ldb_seqnum_t max_sequence;
} ldb_tabinfo_t;

static ldb_tabinfo_t *
tabinfo_create(void) {
  ldb_tabinfo_t *t = ldb_malloc(sizeof(ldb_tabinfo_t));

  ldb_filemeta_init(&t->meta);

  t->max_sequence = 0;

  return t;
}

static void
tabinfo_destroy(ldb_tabinfo_t *t) {
  ldb_filemeta_clear(&t->meta);
  ldb_free(t);
}

/*
 * Repairer
 */

typedef struct ldb_repair_s {
  const char *dbname;
  ldb_comparator_t icmp;
  ldb_bloom_t ipolicy;
  ldb_dbopt_t options;
  int owns_info_log;
  int owns_cache;
  ldb_tables_t *table_cache;
  ldb_edit_t edit;
  ldb_array_t manifests;
  ldb_array_t table_numbers;
  ldb_array_t logs;
  ldb_vector_t tables; /* ldb_tabinfo_t */
  uint64_t next_file_number;
} ldb_repair_t;

static void
repair_init(ldb_repair_t *rep, const char *dbname, const ldb_dbopt_t *options) {
  rep->dbname = dbname;

  if (options->comparator != NULL)
    ldb_ikc_init(&rep->icmp, options->comparator);
  else
    ldb_ikc_init(&rep->icmp, ldb_bytewise_comparator);

  if (options->filter_policy != NULL)
    ldb_ifp_init(&rep->ipolicy, options->filter_policy);
  else
    ldb_ifp_init(&rep->ipolicy, ldb_bloom_default);

  rep->options = ldb_sanitize_options(dbname,
                                      &rep->icmp,
                                      &rep->ipolicy,
                                      options);

  rep->owns_info_log = rep->options.info_log != options->info_log;
  rep->owns_cache = rep->options.block_cache != options->block_cache;

  /* table_cache can be small since we expect each table to be opened once. */
  rep->table_cache = ldb_tables_create(rep->dbname, &rep->options, 10);

  ldb_edit_init(&rep->edit);
  ldb_array_init(&rep->manifests);
  ldb_array_init(&rep->table_numbers);
  ldb_array_init(&rep->logs);
  ldb_vector_init(&rep->tables);

  rep->next_file_number = 1;
}

static void
repair_clear(ldb_repair_t *rep) {
  size_t i;

  ldb_tables_destroy(rep->table_cache);

  if (rep->owns_info_log)
    ldb_logger_destroy(rep->options.info_log);

  if (rep->owns_cache)
    ldb_lru_destroy(rep->options.block_cache);

  for (i = 0; i < rep->tables.length; i++)
    tabinfo_destroy(rep->tables.items[i]);

  ldb_edit_clear(&rep->edit);
  ldb_array_clear(&rep->manifests);
  ldb_array_clear(&rep->table_numbers);
  ldb_array_clear(&rep->logs);
  ldb_vector_clear(&rep->tables);
}

static int
find_files(ldb_repair_t *rep) {
  ldb_filetype_t type;
  uint64_t number;
  char **filenames;
  int i, len;

  len = ldb_get_children(rep->dbname, &filenames);

  if (len < 0)
    return ldb_system_error();

  if (len == 0) {
    ldb_free_children(filenames, len);
    return LDB_IOERR; /* "repair found no files" */
  }

  for (i = 0; i < len; i++) {
    const char *filename = filenames[i];

    if (!ldb_parse_filename(&type, &number, filename))
      continue;

    if (type == LDB_FILE_DESC) {
      ldb_array_push(&rep->manifests, number);
    } else {
      if (number + 1 > rep->next_file_number)
        rep->next_file_number = number + 1;

      if (type == LDB_FILE_LOG)
        ldb_array_push(&rep->logs, number);
      else if (type == LDB_FILE_TABLE)
        ldb_array_push(&rep->table_numbers, number);
    }
  }

  ldb_free_children(filenames, len);

  return LDB_OK;
}

static void
archive_file(ldb_repair_t *rep, const char *fname) {
  /* Move into another directory. e.g. for
   *    dir/foo
   * rename to
   *    dir/lost/foo
   */
  char newfile[LDB_PATH_MAX];
  char newdir[LDB_PATH_MAX];
  char dir[LDB_PATH_MAX];
  const char *base;
  int rc;

  if (!ldb_dirname(dir, sizeof(dir), fname))
    abort(); /* LCOV_EXCL_LINE */

  if (!ldb_join(newdir, sizeof(newdir), dir, "lost"))
    abort(); /* LCOV_EXCL_LINE */

  base = ldb_basename(fname);

  if (!ldb_join(newfile, sizeof(newfile), newdir, base))
    abort(); /* LCOV_EXCL_LINE */

  ldb_create_dir(newdir); /* Ignore error. */

  rc = ldb_rename_file(fname, newfile);

  ldb_log(rep->options.info_log, "Archiving %s: %s", fname, ldb_strerror(rc));
}

static void
report_corruption(ldb_reporter_t *reporter, size_t bytes, int status) {
  /* We print error messages for corruption, but continue repairing. */
  ldb_log(reporter->info_log, "Log #%lu: dropping %d bytes; %s",
                              (unsigned long)reporter->lognum,
                              (signed int)bytes,
                              ldb_strerror(status));
}

static int
convert_log_to_table(ldb_repair_t *rep, uint64_t log) {
  /* Open the log file. */
  char logname[LDB_PATH_MAX];
  ldb_reporter_t reporter;
  ldb_reader_t reader;
  ldb_rfile_t *lfile;
  ldb_buffer_t scratch;
  ldb_slice_t record;
  ldb_batch_t batch;
  ldb_memtable_t *mem;
  ldb_filemeta_t meta;
  ldb_iter_t *iter;
  int rc, counter;

  if (!ldb_log_filename(logname, sizeof(logname), rep->dbname, log))
    abort(); /* LCOV_EXCL_LINE */

  rc = ldb_seqfile_create(logname, &lfile);

  if (rc != LDB_OK)
    return rc;

  /* Create the log reader. */
  reporter.info_log = rep->options.info_log;
  reporter.lognum = log;
  reporter.corruption = report_corruption;

  /* We intentionally make LogReader do checksumming so that
     corruptions cause entire commits to be skipped instead of
     propagating bad information (like overly large sequence
     numbers). */
  ldb_reader_init(&reader, lfile, &reporter, 0, 0);
  ldb_buffer_init(&scratch);
  ldb_slice_init(&record);
  ldb_batch_init(&batch);

  /* Read all the records and add to a memtable. */
  mem = ldb_memtable_create(&rep->icmp);
  counter = 0;

  ldb_memtable_ref(mem);

  while (ldb_reader_read_record(&reader, &record, &scratch)) {
    if (record.size < 12) {
      reporter.corruption(&reporter, record.size, LDB_CORRUPTION);
      continue;
    }

    ldb_batch_set_contents(&batch, &record);

    rc = ldb_batch_insert_into(&batch, mem);

    if (rc == LDB_OK) {
      counter += ldb_batch_count(&batch);
    } else {
      ldb_log(rep->options.info_log, "Log #%lu: ignoring %s",
                                     (unsigned long)log,
                                     ldb_strerror(rc));

      rc = LDB_OK; /* Keep going with rest of file. */
    }
  }

  ldb_batch_clear(&batch);
  ldb_buffer_clear(&scratch);
  ldb_reader_clear(&reader);
  ldb_rfile_destroy(lfile);

  /* Do not record a version edit for this conversion to a Table
     since extract_meta_data() will also generate edits. */
  ldb_filemeta_init(&meta);

  meta.number = rep->next_file_number++;

  iter = ldb_memiter_create(mem);

  rc = ldb_build_table(rep->dbname,
                       &rep->options,
                       rep->table_cache,
                       iter,
                       &meta);

  ldb_iter_destroy(iter);

  ldb_memtable_unref(mem);
  mem = NULL;

  if (rc == LDB_OK) {
    if (meta.file_size > 0)
      ldb_array_push(&rep->table_numbers, meta.number);
  }

  ldb_filemeta_clear(&meta);

  ldb_log(rep->options.info_log, "Log #%lu: %d ops saved to Table #%lu %s",
                                 (unsigned long)log, counter,
                                 (unsigned long)meta.number,
                                 ldb_strerror(rc));

  return rc;
}

static void
convert_logs_to_tables(ldb_repair_t *rep) {
  char fname[LDB_PATH_MAX];
  size_t i;
  int rc;

  for (i = 0; i < rep->logs.length; i++) {
    uint64_t log = rep->logs.items[i];

    if (!ldb_log_filename(fname, sizeof(fname), rep->dbname, log))
      abort(); /* LCOV_EXCL_LINE */

    rc = convert_log_to_table(rep, log);

    if (rc != LDB_OK) {
      ldb_log(rep->options.info_log, "Log #%lu: ignoring conversion error: %s",
                                     (unsigned long)rep->logs.items[i],
                                     ldb_strerror(rc));
    }

    archive_file(rep, fname);
  }
}

static ldb_iter_t *
tableiter_create(ldb_repair_t *rep, const ldb_filemeta_t *meta) {
  /* Same as compaction iterators: if paranoid_checks
     are on, turn on checksum verification. */
  ldb_readopt_t options = *ldb_readopt_default;

  options.verify_checksums = rep->options.paranoid_checks;

  return ldb_tables_iterate(rep->table_cache,
                            &options,
                            meta->number,
                            meta->file_size,
                            NULL);
}

static void
repair_table(ldb_repair_t *rep, const char *src, ldb_tabinfo_t *t) {
  /* We will copy src contents to a new table and then rename the
     new table over the source. */
  ldb_tablegen_t *builder;
  char copy[LDB_PATH_MAX];
  char orig[LDB_PATH_MAX];
  ldb_wfile_t *file;
  ldb_iter_t *iter;
  int counter = 0;
  int rc;

  /* Create builder. */
  if (!ldb_table_filename(copy, sizeof(copy), rep->dbname,
                          rep->next_file_number++)) {
    abort(); /* LCOV_EXCL_LINE */
  }

  rc = ldb_truncfile_create(copy, &file);

  if (rc != LDB_OK) {
    tabinfo_destroy(t);
    return;
  }

  builder = ldb_tablegen_create(&rep->options, file);

  /* Copy data. */
  iter = tableiter_create(rep, &t->meta);
  counter = 0;

  for (ldb_iter_first(iter); ldb_iter_valid(iter); ldb_iter_next(iter)) {
    ldb_slice_t key = ldb_iter_key(iter);
    ldb_slice_t val = ldb_iter_value(iter);

    ldb_tablegen_add(builder, &key, &val);

    counter++;
  }

  ldb_iter_destroy(iter);

  ldb_tables_evict(rep->table_cache, t->meta.number);

  archive_file(rep, src);

  if (counter == 0) {
    ldb_tablegen_abandon(builder); /* Nothing to save. */
  } else {
    rc = ldb_tablegen_finish(builder);

    if (rc == LDB_OK)
      t->meta.file_size = ldb_tablegen_size(builder);
  }

  ldb_tablegen_destroy(builder);
  builder = NULL;

  if (rc == LDB_OK)
    rc = ldb_wfile_close(file);

  ldb_wfile_destroy(file);
  file = NULL;

  if (counter > 0 && rc == LDB_OK) {
    if (!ldb_table_filename(orig, sizeof(orig), rep->dbname, t->meta.number))
      abort(); /* LCOV_EXCL_LINE */

    rc = ldb_rename_file(copy, orig);

    if (rc == LDB_OK) {
      ldb_log(rep->options.info_log, "Table #%lu: %d entries repaired",
                                     (unsigned long)t->meta.number,
                                     counter);

      ldb_vector_push(&rep->tables, t);
      t = NULL;
    }
  }

  if (rc != LDB_OK || counter == 0)
    ldb_remove_file(copy);

  if (t != NULL)
    tabinfo_destroy(t);
}

static void
scan_table(ldb_repair_t *rep, uint64_t number) {
  char fname[LDB_PATH_MAX];
  uint64_t file_size = 0;
  int counter, empty;
  ldb_pkey_t parsed;
  ldb_iter_t *iter;
  ldb_tabinfo_t *t;
  int rc, status;

  if (!ldb_table_filename(fname, sizeof(fname), rep->dbname, number))
    abort(); /* LCOV_EXCL_LINE */

  rc = ldb_file_size(fname, &file_size);

  if (rc != LDB_OK) {
    /* Try alternate file name. */
    if (!ldb_sstable_filename(fname, sizeof(fname), rep->dbname, number))
      abort(); /* LCOV_EXCL_LINE */

    status = ldb_file_size(fname, &file_size);

    if (status == LDB_OK)
      rc = LDB_OK;
  }

  if (rc != LDB_OK) {
    ldb_table_filename(fname, sizeof(fname), rep->dbname, number);
    archive_file(rep, fname);

    ldb_sstable_filename(fname, sizeof(fname), rep->dbname, number);
    archive_file(rep, fname);

    ldb_log(rep->options.info_log, "Table #%lu: dropped: %s",
                                   (unsigned long)number,
                                   ldb_strerror(rc));

    return;
  }

  t = tabinfo_create();
  t->meta.file_size = file_size;
  t->meta.number = number;

  /* Extract metadata by scanning through table. */
  iter = tableiter_create(rep, &t->meta);
  counter = 0;
  empty = 1;

  t->max_sequence = 0;

  for (ldb_iter_first(iter); ldb_iter_valid(iter); ldb_iter_next(iter)) {
    ldb_slice_t key = ldb_iter_key(iter);

    if (!ldb_pkey_import(&parsed, &key)) {
      ldb_log(rep->options.info_log, "Table #%lu: unparsable key",
                                     (unsigned long)t->meta.number);
      continue;
    }

    counter++;

    if (empty) {
      ldb_ikey_copy(&t->meta.smallest, &key);
      empty = 0;
    }

    ldb_ikey_copy(&t->meta.largest, &key);

    if (parsed.sequence > t->max_sequence)
      t->max_sequence = parsed.sequence;
  }

  if (ldb_iter_status(iter) != LDB_OK)
    rc = ldb_iter_status(iter);

  ldb_iter_destroy(iter);

  ldb_log(rep->options.info_log, "Table #%lu: %d entries %s",
                                 (unsigned long)t->meta.number,
                                 counter, ldb_strerror(rc));

  if (rc == LDB_OK)
    ldb_vector_push(&rep->tables, t);
  else
    repair_table(rep, fname, t); /* repair_table archives input file. */
}

static void
extract_meta_data(ldb_repair_t *rep) {
  size_t i;

  for (i = 0; i < rep->table_numbers.length; i++)
    scan_table(rep, rep->table_numbers.items[i]);
}

static int
write_descriptor(ldb_repair_t *rep) {
  ldb_seqnum_t max_sequence = 0;
  char fname[LDB_PATH_MAX];
  char tmp[LDB_PATH_MAX];
  ldb_wfile_t *file;
  size_t i;
  int rc;

  if (!ldb_temp_filename(tmp, sizeof(tmp), rep->dbname, 1))
    abort(); /* LCOV_EXCL_LINE */

  rc = ldb_truncfile_create(tmp, &file);

  if (rc != LDB_OK)
    return rc;

  for (i = 0; i < rep->tables.length; i++) {
    const ldb_tabinfo_t *t = rep->tables.items[i];

    if (max_sequence < t->max_sequence)
      max_sequence = t->max_sequence;
  }

  ldb_edit_set_comparator_name(&rep->edit, rep->icmp.user_comparator->name);
  ldb_edit_set_log_number(&rep->edit, 0);
  ldb_edit_set_next_file(&rep->edit, rep->next_file_number);
  ldb_edit_set_last_sequence(&rep->edit, max_sequence);

  for (i = 0; i < rep->tables.length; i++) {
    const ldb_tabinfo_t *t = rep->tables.items[i];

    ldb_edit_add_file(&rep->edit, 0, t->meta.number,
                                     t->meta.file_size,
                                     &t->meta.smallest,
                                     &t->meta.largest);
  }

  {
    ldb_writer_t log;
    ldb_buffer_t record;

    ldb_writer_init(&log, file, 0);
    ldb_buffer_init(&record);

    ldb_edit_export(&record, &rep->edit);

    rc = ldb_writer_add_record(&log, &record);

    ldb_buffer_clear(&record);
  }

  if (rc == LDB_OK)
    rc = ldb_wfile_close(file);

  ldb_wfile_destroy(file);
  file = NULL;

  if (rc != LDB_OK) {
    ldb_remove_file(tmp);
  } else {
    /* Discard older manifests. */
    for (i = 0; i < rep->manifests.length; i++) {
      uint64_t number = rep->manifests.items[i];

      if (!ldb_desc_filename(fname, sizeof(fname), rep->dbname, number))
        abort(); /* LCOV_EXCL_LINE */

      archive_file(rep, fname);
    }

    /* Install new manifest. */
    if (!ldb_desc_filename(fname, sizeof(fname), rep->dbname, 1))
      abort(); /* LCOV_EXCL_LINE */

    rc = ldb_rename_file(tmp, fname);

    if (rc == LDB_OK)
      rc = ldb_set_current_file(rep->dbname, 1);
    else
      ldb_remove_file(tmp);
  }

  return rc;
}

static int
repair_run(ldb_repair_t *rep) {
  int rc = find_files(rep);

  if (rc == LDB_OK) {
    convert_logs_to_tables(rep);
    extract_meta_data(rep);

    rc = write_descriptor(rep);
  }

  if (rc == LDB_OK) {
    int64_t bytes = 0;
    size_t i;

    for (i = 0; i < rep->tables.length; i++) {
      const ldb_tabinfo_t *t = rep->tables.items[i];
      bytes += t->meta.file_size;
    }

    ldb_log(rep->options.info_log,
            "**** Repaired database %s; "
            "recovered %d files; %.0f bytes. "
            "Some data may have been lost. "
            "****", rep->dbname,
            (int)rep->tables.length,
            (double)bytes);
  }

  return rc;
}

int
ldb_repair(const char *dbname, const ldb_dbopt_t *options) {
  char path[LDB_PATH_MAX];
  ldb_repair_t rep;
  int rc;

  ldb_crc32c_init();

  if (options == NULL)
    return LDB_INVALID;

  if (options->filter_policy != NULL) {
    if (strlen(options->filter_policy->name) > 64)
      return LDB_INVALID;
  }

  if (!ldb_path_absolute(path, sizeof(path) - 35, dbname))
    return LDB_INVALID;

  repair_init(&rep, path, options);

  rc = repair_run(&rep);

  repair_clear(&rep);

  return rc;
}
