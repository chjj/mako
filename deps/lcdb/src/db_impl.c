/*!
 * db_impl.c - database implementation for lcdb
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

#include "table/iterator.h"
#include "table/merger.h"
#include "table/table.h"
#include "table/table_builder.h"

#include "util/array.h"
#include "util/atomic.h"
#include "util/bloom.h"
#include "util/buffer.h"
#include "util/cache.h"
#include "util/coding.h"
#include "util/comparator.h"
#include "util/crc32c.h"
#include "util/env.h"
#include "util/internal.h"
#include "util/options.h"
#include "util/port.h"
#include "util/rbt.h"
#include "util/slice.h"
#include "util/status.h"
#include "util/strutil.h"
#include "util/thread_pool.h"
#include "util/vector.h"

#include "builder.h"
#include "db_impl.h"
#include "db_iter.h"
#include "dbformat.h"
#include "filename.h"
#include "log_format.h"
#include "log_reader.h"
#include "log_writer.h"
#include "memtable.h"
#include "snapshot.h"
#include "table_cache.h"
#include "version_edit.h"
#include "version_set.h"
#include "write_batch.h"

/*
 * DBImpl::ManualCompaction
 */

/* Information for a manual compaction. */
typedef struct ldb_manual_s {
  int level;
  int done;
  const ldb_ikey_t *begin; /* null means beginning of key range. */
  const ldb_ikey_t *end;   /* null means end of key range. */
  ldb_ikey_t tmp_storage;  /* Used to keep track of compaction progress. */
} ldb_manual_t;

static void
ldb_manual_init(ldb_manual_t *m, int level) {
  m->level = level;
  m->done = 0;
  m->begin = NULL;
  m->end = NULL;

  ldb_ikey_init(&m->tmp_storage);
}

static void
ldb_manual_clear(ldb_manual_t *m) {
  ldb_ikey_clear(&m->tmp_storage);
}

/*
 * DBImpl::CompactionStats
 */

/* Per level compaction stats. stats[level] stores the stats for
   compactions that produced data for the specified "level". */
typedef struct ldb_stats_s {
  int64_t micros;
  int64_t bytes_read;
  int64_t bytes_written;
} ldb_stats_t;

static void
ldb_stats_init(ldb_stats_t *c) {
  c->micros = 0;
  c->bytes_read = 0;
  c->bytes_written = 0;
}

static void
ldb_stats_add(ldb_stats_t *z, const ldb_stats_t *x) {
  z->micros += x->micros;
  z->bytes_read += x->bytes_read;
  z->bytes_written += x->bytes_written;
}

/*
 * DBImpl::Writer
 */

/* Information kept for every waiting writer. */
typedef struct ldb_waiter_s {
  int status;
  ldb_batch_t *batch;
  int sync;
  int done;
  ldb_cond_t cv;
  struct ldb_waiter_s *next;
} ldb_waiter_t;

static void
ldb_waiter_init(ldb_waiter_t *w) {
  w->status = LDB_OK;
  w->batch = NULL;
  w->sync = 0;
  w->done = 0;
  w->next = NULL;

  ldb_cond_init(&w->cv);
}

static void
ldb_waiter_clear(ldb_waiter_t *w) {
  ldb_cond_destroy(&w->cv);
}

/*
 * Writer Queue
 */

typedef struct ldb_queue_s {
  ldb_waiter_t *head;
  ldb_waiter_t *tail;
  int length;
} ldb_queue_t;

static void
ldb_queue_init(ldb_queue_t *queue) {
  queue->head = NULL;
  queue->tail = NULL;
  queue->length = 0;
}

static void
ldb_queue_push(ldb_queue_t *queue, ldb_waiter_t *writer) {
  if (queue->head == NULL)
    queue->head = writer;

  if (queue->tail != NULL)
    queue->tail->next = writer;

  queue->tail = writer;
  queue->length++;
}

static ldb_waiter_t *
ldb_queue_shift(ldb_queue_t *queue) {
  ldb_waiter_t *writer = queue->head;

  if (writer == NULL)
    abort(); /* LCOV_EXCL_LINE */

  queue->head = writer->next;

  if (queue->head == NULL)
    queue->tail = NULL;

  queue->length--;

  writer->next = NULL;

  return writer;
}

/*
 * CompactionState::Output
 */

/* Files produced by compaction. */
typedef struct ldb_output_s {
  uint64_t number;
  uint64_t file_size;
  ldb_ikey_t smallest, largest;
} ldb_output_t;

static ldb_output_t *
ldb_output_create(uint64_t number) {
  ldb_output_t *out = ldb_malloc(sizeof(ldb_output_t));

  out->number = number;
  out->file_size = 0;

  ldb_ikey_init(&out->smallest);
  ldb_ikey_init(&out->largest);

  return out;
}

static void
ldb_output_destroy(ldb_output_t *out) {
  ldb_ikey_clear(&out->smallest);
  ldb_ikey_clear(&out->largest);
  ldb_free(out);
}

/*
 * CompactionState
 */

typedef struct ldb_cstate_s {
  ldb_compaction_t *compaction;

  /* Sequence numbers < smallest_snapshot are not significant since we
     will never have to service a snapshot below smallest_snapshot.
     Therefore if we have seen a sequence number S <= smallest_snapshot,
     we can drop all entries for the same key with sequence numbers < S. */
  ldb_seqnum_t smallest_snapshot;

  ldb_vector_t outputs; /* ldb_output_t */

  /* State kept for output being generated. */
  ldb_wfile_t *outfile;
  ldb_tablegen_t *builder;

  uint64_t total_bytes;
} ldb_cstate_t;

static ldb_cstate_t *
ldb_cstate_create(ldb_compaction_t *c) {
  ldb_cstate_t *state = ldb_malloc(sizeof(ldb_cstate_t));

  state->compaction = c;
  state->smallest_snapshot = 0;
  state->outfile = NULL;
  state->builder = NULL;
  state->total_bytes = 0;

  ldb_vector_init(&state->outputs);

  return state;
}

static void
ldb_cstate_destroy(ldb_cstate_t *state) {
  size_t i;

  for (i = 0; i < state->outputs.length; i++)
    ldb_output_destroy(state->outputs.items[i]);

  ldb_vector_clear(&state->outputs);
  ldb_free(state);
}

static ldb_output_t *
ldb_cstate_top(ldb_cstate_t *state) {
  return ldb_vector_top(&state->outputs);
}

/*
 * IterState
 */

typedef struct ldb_istate_s {
  ldb_mutex_t *mu;
  /* All guarded by mu. */
  ldb_version_t *version;
  ldb_memtable_t *mem;
  ldb_memtable_t *imm;
} ldb_istate_t;

static ldb_istate_t *
ldb_istate_create(ldb_mutex_t *mutex,
                  ldb_memtable_t *mem,
                  ldb_memtable_t *imm,
                  ldb_version_t *version) {
  ldb_istate_t *state = ldb_malloc(sizeof(ldb_istate_t));

  state->mu = mutex;
  state->version = version;
  state->mem = mem;
  state->imm = imm;

  return state;
}

static void
ldb_istate_destroy(ldb_istate_t *state) {
  ldb_mutex_lock(state->mu);

  ldb_memtable_unref(state->mem);

  if (state->imm != NULL)
    ldb_memtable_unref(state->imm);

  ldb_version_unref(state->version);

  ldb_mutex_unlock(state->mu);

  ldb_free(state);
}

/*
 * Helpers
 */

static const int non_table_cache_files = 10;

/* Fix user-supplied options to be reasonable. */
#define clip_to_range(val, min, max) do { \
  if ((val) > (max)) (val) = (max);       \
  if ((val) < (min)) (val) = (min);       \
} while (0)

ldb_dbopt_t
ldb_sanitize_options(const char *dbname,
                     const ldb_comparator_t *icmp,
                     const ldb_bloom_t *ipolicy,
                     const ldb_dbopt_t *src) {
  ldb_dbopt_t result = *src;
  int rc = LDB_OK;

  result.comparator = icmp;
  result.filter_policy = (src->filter_policy != NULL) ? ipolicy : NULL;

  clip_to_range(result.max_open_files, 64 + non_table_cache_files, 50000);
  clip_to_range(result.write_buffer_size, 64 << 10, 1 << 30);
  clip_to_range(result.max_file_size, 1 << 20, 1 << 30);
  clip_to_range(result.block_size, 1 << 10, 4 << 20);

  if (result.info_log == NULL) {
    char info[LDB_PATH_MAX];
    char old[LDB_PATH_MAX];

    if (!ldb_info_filename(info, sizeof(info), dbname))
      rc = LDB_INVALID;

    if (!ldb_oldinfo_filename(old, sizeof(old), dbname))
      rc = LDB_INVALID;

    if (rc == LDB_OK) {
      /* Open a log file in the same directory as the db. */
      ldb_create_dir(dbname); /* In case it does not exist. */
      ldb_rename_file(info, old);

      rc = ldb_logger_open(info, &result.info_log);

      if (rc != LDB_OK) {
        /* No place suitable for logging.*/
        result.info_log = NULL;
      }
    }
  }

  if (result.block_cache == NULL)
    result.block_cache = ldb_lru_create(8 << 20);

  return result;
}

static int
table_cache_size(const ldb_dbopt_t *sanitized_options) {
  /* Reserve ten files or so for other uses and give the rest to TableCache. */
  return sanitized_options->max_open_files - non_table_cache_files;
}

/*
 * DBImpl
 */

struct ldb_s {
  /* Constant after construction. */
  ldb_comparator_t user_comparator;
  ldb_bloom_t user_filter_policy;
  ldb_comparator_t internal_comparator;
  ldb_bloom_t internal_filter_policy;
  ldb_dbopt_t options; /* options.comparator == &internal_comparator */
  int owns_info_log;
  int owns_cache;
  char dbname[LDB_PATH_MAX];

  /* table_cache provides its own synchronization. */
  ldb_tables_t *table_cache;

  /* Lock over the persistent DB state. Non-null iff successfully acquired. */
  ldb_filelock_t *db_lock;

  /* State below is protected by mutex. */
  ldb_mutex_t mutex;
  ldb_atomic(int) shutting_down;
  ldb_cond_t background_work_finished_signal;
  ldb_memtable_t *mem;
  ldb_memtable_t *imm; /* Memtable being compacted. */
  ldb_atomic(int) has_imm; /* So bg thread can detect non-null imm. */
  ldb_wfile_t *logfile;
  uint64_t logfile_number;
  ldb_writer_t *log;
  uint32_t seed; /* For sampling. */

  /* Queue of writers. */
  ldb_queue_t writers;
  ldb_batch_t *tmp_batch;

  ldb_snaplist_t snapshots;

  /* Set of table files to protect from deletion because they are
     part of ongoing compactions. */
  rb_set64_t pending_outputs;

  /* Thread pool. */
  ldb_pool_t *pool;

  /* Has a background compaction been scheduled or is running? */
  int background_compaction_scheduled;

  ldb_manual_t *manual_compaction;

  ldb_versions_t *versions;

  /* Have we encountered a background error in paranoid mode? */
  int bg_error;

  ldb_stats_t stats[LDB_NUM_LEVELS];
};

static ldb_t *
ldb_create(const char *dbname, const ldb_dbopt_t *options) {
  ldb_t *db = ldb_malloc(sizeof(ldb_t));
  size_t len = strlen(dbname);
  int i;

  assert(len + 1 <= sizeof(db->dbname));

  memcpy(db->dbname, dbname, len + 1);

  if (options->comparator != NULL) {
    db->user_comparator = *options->comparator;
    ldb_ikc_init(&db->internal_comparator, &db->user_comparator);
  } else {
    ldb_ikc_init(&db->internal_comparator, ldb_bytewise_comparator);
  }

  if (options->filter_policy != NULL) {
    db->user_filter_policy = *options->filter_policy;
    ldb_ifp_init(&db->internal_filter_policy, &db->user_filter_policy);
  } else {
    ldb_ifp_init(&db->internal_filter_policy, ldb_bloom_default);
  }

  db->options = ldb_sanitize_options(db->dbname,
                                     &db->internal_comparator,
                                     &db->internal_filter_policy,
                                     options);

  db->owns_info_log = (db->options.info_log != options->info_log);
  db->owns_cache = (db->options.block_cache != options->block_cache);

  (void)db->dbname;

  db->table_cache = ldb_tables_create(db->dbname,
                                      &db->options,
                                      table_cache_size(&db->options));

  db->db_lock = NULL;

  ldb_mutex_init(&db->mutex);

  ldb_atomic_init(&db->shutting_down, 0);

  ldb_cond_init(&db->background_work_finished_signal);

  db->mem = NULL;
  db->imm = NULL;

  ldb_atomic_init(&db->has_imm, 0);

  db->logfile = NULL;
  db->logfile_number = 0;
  db->log = NULL;
  db->seed = 0;

  ldb_queue_init(&db->writers);

  db->tmp_batch = ldb_batch_create();

  ldb_snaplist_init(&db->snapshots);
  rb_set64_init(&db->pending_outputs);

  db->pool = ldb_pool_create(1);
  db->background_compaction_scheduled = 0;
  db->manual_compaction = NULL;

  db->versions = ldb_versions_create(db->dbname,
                                     &db->options,
                                     db->table_cache,
                                     &db->internal_comparator);

  db->bg_error = LDB_OK;

  for (i = 0; i < LDB_NUM_LEVELS; i++)
    ldb_stats_init(&db->stats[i]);

  return db;
}

static void
ldb_destroy_internal(ldb_t *db) {
  /* Wait for background work to finish. */
  ldb_mutex_lock(&db->mutex);

  ldb_atomic_store(&db->shutting_down, 1, ldb_order_release);

  while (db->background_compaction_scheduled)
    ldb_cond_wait(&db->background_work_finished_signal, &db->mutex);

  ldb_mutex_unlock(&db->mutex);

  ldb_pool_destroy(db->pool);

  if (db->db_lock != NULL)
    ldb_unlock_file(db->db_lock);

  ldb_versions_destroy(db->versions);

  if (db->mem != NULL)
    ldb_memtable_unref(db->mem);

  if (db->imm != NULL)
    ldb_memtable_unref(db->imm);

  ldb_batch_destroy(db->tmp_batch);

  if (db->log != NULL)
    ldb_writer_destroy(db->log);

  if (db->logfile != NULL)
    ldb_wfile_destroy(db->logfile);

  ldb_tables_destroy(db->table_cache);

  if (db->owns_info_log)
    ldb_logger_destroy(db->options.info_log);

  if (db->owns_cache)
    ldb_lru_destroy(db->options.block_cache);

  assert(db->writers.length == 0);
  assert(ldb_snaplist_empty(&db->snapshots));

  rb_set64_clear(&db->pending_outputs);

  ldb_mutex_destroy(&db->mutex);
  ldb_cond_destroy(&db->background_work_finished_signal);

  ldb_free(db);
}

static const ldb_comparator_t *
ldb_user_comparator(const ldb_t *db) {
  return db->internal_comparator.user_comparator;
}

static int
ldb_new_db(ldb_t *db) {
  char manifest[LDB_PATH_MAX];
  ldb_edit_t new_db;
  ldb_wfile_t *file;
  int rc;

  if (!ldb_desc_filename(manifest, sizeof(manifest), db->dbname, 1))
    return LDB_INVALID;

  rc = ldb_truncfile_create(manifest, &file);

  if (rc != LDB_OK)
    return rc;

  ldb_edit_init(&new_db);
  ldb_edit_set_comparator_name(&new_db, ldb_user_comparator(db)->name);
  ldb_edit_set_log_number(&new_db, 0);
  ldb_edit_set_next_file(&new_db, 2);
  ldb_edit_set_last_sequence(&new_db, 0);

  {
    ldb_writer_t log;
    ldb_buffer_t record;

    ldb_writer_init(&log, file, 0);
    ldb_buffer_init(&record);

    ldb_edit_export(&record, &new_db);

    rc = ldb_writer_add_record(&log, &record);

    if (rc == LDB_OK)
      rc = ldb_wfile_sync(file);

    if (rc == LDB_OK)
      rc = ldb_wfile_close(file);

    ldb_buffer_clear(&record);
  }

  ldb_wfile_destroy(file);

  if (rc == LDB_OK) {
    /* Make "CURRENT" file that points to the new manifest file. */
    rc = ldb_set_current_file(db->dbname, 1);
  } else {
    ldb_remove_file(manifest);
  }

  ldb_edit_clear(&new_db);

  return rc;
}

static void
ldb_maybe_ignore_error(const ldb_t *db, int *status) {
  if (*status == LDB_OK || db->options.paranoid_checks) {
    ; /* No change needed. */
  } else {
    ldb_log(db->options.info_log, "Ignoring error %s",
                                  ldb_strerror(*status));
    *status = LDB_OK;
  }
}

/* Delete any unneeded files and stale in-memory entries. */
static void
ldb_remove_obsolete_files(ldb_t *db) {
  char path[LDB_PATH_MAX];
  char **filenames = NULL;
  ldb_vector_t to_delete;
  ldb_filetype_t type;
  rb_set64_t live;
  uint64_t number;
  int i, len;

  ldb_mutex_assert_held(&db->mutex);

  if (db->bg_error != LDB_OK) {
    /* After a background error, we don't know whether a new version may
       or may not have been committed, so we cannot safely garbage collect. */
    return;
  }

  rb_set64_init(&live);
  ldb_vector_init(&to_delete);

  /* Make a set of all of the live files. */
  rb_set64_copy(&live, &db->pending_outputs);

  ldb_versions_add_files(db->versions, &live);

  len = ldb_get_children(db->dbname, &filenames); /* Ignoring errors. */

  for (i = 0; i < len; i++) {
    const char *filename = filenames[i];

    if (ldb_parse_filename(&type, &number, filename)) {
      int keep = 1;

      switch (type) {
        case LDB_FILE_LOG:
          keep = ((number >= db->versions->log_number) ||
                  (number == db->versions->prev_log_number));
          break;
        case LDB_FILE_DESC:
          /* Keep my manifest file, and any newer incarnations'
             (in case there is a race that allows other incarnations). */
          keep = (number >= db->versions->manifest_file_number);
          break;
        case LDB_FILE_TABLE:
          keep = rb_set64_has(&live, number);
          break;
        case LDB_FILE_TEMP:
          /* Any temp files that are currently being written to must
             be recorded in pending_outputs, which is inserted into "live". */
          keep = rb_set64_has(&live, number);
          break;
        case LDB_FILE_CURRENT:
        case LDB_FILE_LOCK:
        case LDB_FILE_INFO:
          keep = 1;
          break;
      }

      if (!keep) {
        ldb_vector_push(&to_delete, filename);

        if (type == LDB_FILE_TABLE)
          ldb_tables_evict(db->table_cache, number);

        ldb_log(db->options.info_log, "Delete type=%d #%lu",
                                      (signed int)type,
                                      (unsigned long)number);
      }
    }
  }

  /* While deleting all files unblock other threads. All files being deleted
     have unique names which will not collide with newly created files and
     are therefore safe to delete while allowing other threads to proceed. */
  ldb_mutex_unlock(&db->mutex);

  for (i = 0; i < (int)to_delete.length; i++) {
    const char *filename = to_delete.items[i];

    if (!ldb_join(path, sizeof(path), db->dbname, filename))
      continue;

    ldb_remove_file(path);
  }

  rb_set64_clear(&live);
  ldb_vector_clear(&to_delete);

  if (filenames != NULL)
    ldb_free_children(filenames, len);

  ldb_mutex_lock(&db->mutex);
}

static int
ldb_write_level0_table(ldb_t *db, ldb_memtable_t *mem,
                                  ldb_edit_t *edit,
                                  ldb_version_t *base) {
  int64_t start_micros;
  ldb_filemeta_t meta;
  ldb_stats_t stats;
  ldb_iter_t *iter;
  int rc = LDB_OK;
  int level = 0;

  ldb_mutex_assert_held(&db->mutex);

  ldb_filemeta_init(&meta);
  ldb_stats_init(&stats);

  start_micros = ldb_now_usec();

  meta.number = ldb_versions_new_file_number(db->versions);

  rb_set64_put(&db->pending_outputs, meta.number);

  iter = ldb_memiter_create(mem);

  ldb_log(db->options.info_log, "Level-0 table #%lu: started",
                                (unsigned long)meta.number);

  {
    ldb_mutex_unlock(&db->mutex);

    rc = ldb_build_table(db->dbname,
                         &db->options,
                         db->table_cache,
                         iter,
                         &meta);

    ldb_mutex_lock(&db->mutex);
  }

  ldb_log(db->options.info_log, "Level-0 table #%lu: %lu bytes %s",
                                (unsigned long)meta.number,
                                (unsigned long)meta.file_size,
                                ldb_strerror(rc));

  ldb_iter_destroy(iter);

  rb_set64_del(&db->pending_outputs, meta.number);

  /* Note that if file_size is zero, the file has been deleted and
     should not be added to the manifest. */
  if (rc == LDB_OK && meta.file_size > 0) {
    if (base != NULL) {
      ldb_slice_t min_user_key = ldb_ikey_user_key(&meta.smallest);
      ldb_slice_t max_user_key = ldb_ikey_user_key(&meta.largest);

      level = ldb_version_pick_level_for_memtable_output(base,
                                                         &min_user_key,
                                                         &max_user_key);
    }

    ldb_edit_add_file(edit, level,
                      meta.number,
                      meta.file_size,
                      &meta.smallest,
                      &meta.largest);
  }

  stats.micros = ldb_now_usec() - start_micros;
  stats.bytes_written = meta.file_size;

  ldb_stats_add(&db->stats[level], &stats);

  ldb_filemeta_clear(&meta);

  return rc;
}

static void
report_corruption(ldb_reporter_t *report, size_t bytes, int status) {
  ldb_log(report->info_log, "%s%s: dropping %d bytes; %s",
          report->status == NULL ? "(ignoring error) " : "",
          report->fname, (int)bytes, ldb_strerror(status));

  if (report->status != NULL && *report->status == LDB_OK)
    *report->status = status;
}

static int
ldb_recover_log_file(ldb_t *db, uint64_t log_number,
                                int last_log,
                                int *save_manifest,
                                ldb_edit_t *edit,
                                ldb_seqnum_t *max_sequence) {
  char fname[LDB_PATH_MAX];
  ldb_reporter_t reporter;
  ldb_rfile_t *file;
  int rc = LDB_OK;
  ldb_buffer_t buf;
  ldb_slice_t record;
  ldb_batch_t batch;
  int compactions = 0;
  ldb_memtable_t *mem = NULL;
  ldb_reader_t reader;

  ldb_mutex_assert_held(&db->mutex);

  /* Open the log file. */
  if (!ldb_log_filename(fname, sizeof(fname), db->dbname, log_number))
    return LDB_INVALID;

  rc = ldb_seqfile_create(fname, &file);

  if (rc != LDB_OK) {
    ldb_maybe_ignore_error(db, &rc);
    return rc;
  }

  /* Create the log reader. */
  reporter.fname = fname;
  reporter.status = (db->options.paranoid_checks ? &rc : NULL);
  reporter.info_log = db->options.info_log;
  reporter.corruption = report_corruption;

  /* We intentionally make the log reader do checksumming even if
     paranoid_checks==0 so that corruptions cause entire commits
     to be skipped instead of propagating bad information (like
     overly large sequence numbers). */
  ldb_reader_init(&reader, file, &reporter, 1, 0);
  ldb_batch_init(&batch);
  ldb_buffer_init(&buf);

  ldb_log(db->options.info_log, "Recovering log #%lu",
                                (unsigned long)log_number);

  /* Read all the records and add to a memtable. */
  while (ldb_reader_read_record(&reader, &record, &buf) && rc == LDB_OK) {
    ldb_seqnum_t last_seq;

    if (record.size < 12) {
      /* "log record too small" */
      reporter.corruption(&reporter, record.size, LDB_CORRUPTION);
      continue;
    }

    ldb_batch_set_contents(&batch, &record);

    if (mem == NULL) {
      mem = ldb_memtable_create(&db->internal_comparator);
      ldb_memtable_ref(mem);
    }

    rc = ldb_batch_insert_into(&batch, mem);

    ldb_maybe_ignore_error(db, &rc);

    if (rc != LDB_OK)
      break;

    last_seq = ldb_batch_sequence(&batch) + ldb_batch_count(&batch) - 1;

    if (last_seq > *max_sequence)
      *max_sequence = last_seq;

    if (ldb_memtable_usage(mem) > db->options.write_buffer_size) {
      compactions++;
      *save_manifest = 1;

      rc = ldb_write_level0_table(db, mem, edit, NULL);

      ldb_memtable_unref(mem);
      mem = NULL;

      if (rc != LDB_OK) {
        /* Reflect errors immediately so that conditions like full
           file-systems cause the ldb_open() to fail. */
        break;
      }
    }
  }

  ldb_buffer_clear(&buf);
  ldb_batch_clear(&batch);
  ldb_reader_clear(&reader);
  ldb_rfile_destroy(file);

  /* See if we should keep reusing the last log file. */
  if (rc == LDB_OK && db->options.reuse_logs && last_log && compactions == 0) {
    uint64_t lfile_size;

    assert(db->logfile == NULL);
    assert(db->log == NULL);
    assert(db->mem == NULL);

    if (ldb_file_size(fname, &lfile_size) == LDB_OK &&
        ldb_appendfile_create(fname, &db->logfile) == LDB_OK) {
      ldb_log(db->options.info_log, "Reusing old log %s", fname);

      db->log = ldb_writer_create(db->logfile, lfile_size);
      db->logfile_number = log_number;

      if (mem != NULL) {
        db->mem = mem;
        mem = NULL;
      } else {
        /* mem can be NULL if lognum exists but was empty. */
        db->mem = ldb_memtable_create(&db->internal_comparator);
        ldb_memtable_ref(db->mem);
      }
    }
  }

  if (mem != NULL) {
    /* mem did not get reused; compact it. */
    if (rc == LDB_OK) {
      *save_manifest = 1;
      rc = ldb_write_level0_table(db, mem, edit, NULL);
    }

    ldb_memtable_unref(mem);
  }

  return rc;
}

static int
compare_ascending(uint64_t x, uint64_t y) {
  return LDB_CMP(x, y);
}

/* Recover the descriptor from persistent storage. May do a significant
   amount of work to recover recently logged updates. Any changes to
   be made to the descriptor are added to *edit. */
static int
ldb_recover(ldb_t *db, ldb_edit_t *edit, int *save_manifest) {
  uint64_t min_log, prev_log, number;
  ldb_seqnum_t max_sequence = 0;
  char path[LDB_PATH_MAX];
  char **filenames = NULL;
  rb_set64_t expected;
  ldb_filetype_t type;
  ldb_array_t logs;
  int rc = LDB_OK;
  int i, len;

  ldb_mutex_assert_held(&db->mutex);

  /* Ignore error from create_dir since the creation of the DB is
     committed only when the descriptor is created, and this directory
     may already exist from a previous failed creation attempt. */
  ldb_create_dir(db->dbname);

  assert(db->db_lock == NULL);

  if (!ldb_lock_filename(path, sizeof(path), db->dbname))
    return LDB_INVALID;

  rc = ldb_lock_file(path, &db->db_lock);

  if (rc != LDB_OK)
    return rc;

  if (!ldb_current_filename(path, sizeof(path), db->dbname))
    return LDB_INVALID;

  if (!ldb_file_exists(path)) {
    if (db->options.create_if_missing) {
      ldb_log(db->options.info_log,
              "Creating DB %s since it was missing.",
              db->dbname);

      rc = ldb_new_db(db);

      if (rc != LDB_OK)
        return rc;
    } else {
      return LDB_INVALID; /* "does not exist (create_if_missing is false)" */
    }
  } else {
    if (db->options.error_if_exists)
      return LDB_INVALID; /* "exists (error_if_exists is true)" */
  }

  rc = ldb_versions_recover(db->versions, save_manifest);

  if (rc != LDB_OK)
    return rc;

  /* Recover from all newer log files than the ones named in the
   * descriptor (new log files may have been added by the previous
   * incarnation without registering them in the descriptor).
   *
   * Note that prev_log_number is no longer used, but we pay
   * attention to it in case we are recovering a database
   * produced by an older version of leveldb.
   */
  min_log = db->versions->log_number;
  prev_log = db->versions->prev_log_number;

  len = ldb_get_children(db->dbname, &filenames);

  if (len < 0)
    return ldb_system_error();

  rb_set64_init(&expected);
  ldb_array_init(&logs);

  ldb_versions_add_files(db->versions, &expected);

  for (i = 0; i < len; i++) {
    if (ldb_parse_filename(&type, &number, filenames[i])) {
      rb_set64_del(&expected, number);

      if (type == LDB_FILE_LOG && ((number >= min_log) || (number == prev_log)))
        ldb_array_push(&logs, number);
    }
  }

  ldb_free_children(filenames, len);

  if (expected.size != 0) {
    rc = LDB_CORRUPTION; /* "[expected.size] missing files" */
    goto fail;
  }

  /* Recover in the order in which the logs were generated. */
  ldb_array_sort(&logs, compare_ascending);

  for (i = 0; i < (int)logs.length; i++) {
    rc = ldb_recover_log_file(db, logs.items[i],
                                  (i == (int)logs.length - 1),
                                  save_manifest,
                                  edit,
                                  &max_sequence);

    if (rc != LDB_OK)
      goto fail;

    /* The previous incarnation may not have written any MANIFEST
       records after allocating this log number. So we manually
       update the file number allocation counter in VersionSet. */
    ldb_versions_mark_file_number(db->versions, logs.items[i]);
  }

  if (db->versions->last_sequence < max_sequence)
    db->versions->last_sequence = max_sequence;

  rc = LDB_OK;
fail:
  rb_set64_clear(&expected);
  ldb_array_clear(&logs);
  return rc;
}

static void
ldb_record_background_error(ldb_t *db, int status) {
  ldb_mutex_assert_held(&db->mutex);

  if (db->bg_error == LDB_OK) {
    db->bg_error = status;

    ldb_cond_broadcast(&db->background_work_finished_signal);
  }
}

/* Compact the in-memory write buffer to disk. Switches to a new
   log-file/memtable and writes a new descriptor iff successful.
   Errors are recorded in bg_error. */
static void
ldb_compact_memtable(ldb_t *db) {
  ldb_version_t *base;
  ldb_edit_t edit;
  int rc = LDB_OK;

  ldb_edit_init(&edit);

  ldb_mutex_assert_held(&db->mutex);

  assert(db->imm != NULL);

  /* Save the contents of the memtable as a new Table. */
  base = db->versions->current;

  ldb_version_ref(base);

  rc = ldb_write_level0_table(db, db->imm, &edit, base);

  ldb_version_unref(base);

  if (rc == LDB_OK && ldb_atomic_load(&db->shutting_down, ldb_order_acquire))
    rc = LDB_IOERR; /* "Deleting DB during memtable compaction" */

  /* Replace immutable memtable with the generated Table. */
  if (rc == LDB_OK) {
    ldb_edit_set_prev_log_number(&edit, 0);
    ldb_edit_set_log_number(&edit, db->logfile_number); /* Earlier logs no
                                                           longer needed. */

    rc = ldb_versions_apply(db->versions, &edit, &db->mutex);
  }

  if (rc == LDB_OK) {
    /* Commit to the new state. */
    ldb_memtable_unref(db->imm);
    db->imm = NULL;
    ldb_atomic_store(&db->has_imm, 0, ldb_order_release);
    ldb_remove_obsolete_files(db);
  } else {
    ldb_record_background_error(db, rc);
  }

  ldb_edit_clear(&edit);
}

static int
ldb_open_compaction_output_file(ldb_t *db, ldb_cstate_t *state) {
  char fname[LDB_PATH_MAX];
  uint64_t file_number;
  int rc = LDB_OK;

  assert(state != NULL);
  assert(state->builder == NULL);

  {
    ldb_mutex_lock(&db->mutex);

    file_number = ldb_versions_new_file_number(db->versions);

    rb_set64_put(&db->pending_outputs, file_number);

    ldb_vector_push(&state->outputs, ldb_output_create(file_number));

    ldb_mutex_unlock(&db->mutex);
  }

  /* Make the output file. */
  if (!ldb_table_filename(fname, sizeof(fname), db->dbname, file_number))
    return LDB_INVALID;

  rc = ldb_truncfile_create(fname, &state->outfile);

  if (rc == LDB_OK)
    state->builder = ldb_tablegen_create(&db->options, state->outfile);

  return rc;
}

static int
ldb_finish_compaction_output_file(ldb_t *db, ldb_cstate_t *state,
                                             ldb_iter_t *input) {
  uint64_t output_number, current_entries, current_bytes;
  int rc = LDB_OK;

  assert(state != NULL);
  assert(state->outfile != NULL);
  assert(state->builder != NULL);

  output_number = ldb_cstate_top(state)->number;

  assert(output_number != 0);

  /* Check for iterator errors. */
  rc = ldb_iter_status(input);

  current_entries = ldb_tablegen_entries(state->builder);

  if (rc == LDB_OK)
    rc = ldb_tablegen_finish(state->builder);
  else
    ldb_tablegen_abandon(state->builder);

  current_bytes = ldb_tablegen_size(state->builder);

  ldb_cstate_top(state)->file_size = current_bytes;

  state->total_bytes += current_bytes;

  ldb_tablegen_destroy(state->builder);
  state->builder = NULL;

  /* Finish and check for file errors. */
  if (rc == LDB_OK)
    rc = ldb_wfile_sync(state->outfile);

  if (rc == LDB_OK)
    rc = ldb_wfile_close(state->outfile);

  ldb_wfile_destroy(state->outfile);
  state->outfile = NULL;

  if (rc == LDB_OK && current_entries > 0) {
    /* Verify that the table is usable. */
    ldb_iter_t *iter = ldb_tables_iterate(db->table_cache,
                                          ldb_readopt_default,
                                          output_number,
                                          current_bytes,
                                          NULL);

    rc = ldb_iter_status(iter);

    ldb_iter_destroy(iter);

    if (rc == LDB_OK) {
      ldb_log(db->options.info_log,
              "Generated table #%lu@%d: %lu keys, %lu bytes",
              (unsigned long)output_number,
              state->compaction->level,
              (unsigned long)current_entries,
              (unsigned long)current_bytes);
    }
  }

  return rc;
}

static int
ldb_install_compaction_results(ldb_t *db, ldb_cstate_t *state) {
  ldb_edit_t *edit = &state->compaction->edit;
  int level;
  size_t i;

  ldb_mutex_assert_held(&db->mutex);

  ldb_log(db->options.info_log, "Compacted %d@%d + %d@%d files => %ld bytes",
          (int)state->compaction->inputs[0].length,
          state->compaction->level + 0,
          (int)state->compaction->inputs[1].length,
          state->compaction->level + 1,
          (long)state->total_bytes);

  /* Add compaction outputs. */
  ldb_compaction_add_input_deletions(state->compaction, edit);

  level = state->compaction->level;

  for (i = 0; i < state->outputs.length; i++) {
    const ldb_output_t *out = state->outputs.items[i];

    ldb_edit_add_file(edit, level + 1,
                      out->number,
                      out->file_size,
                      &out->smallest,
                      &out->largest);
  }

  return ldb_versions_apply(db->versions, edit, &db->mutex);
}

static int
ldb_do_compaction_work(ldb_t *db, ldb_cstate_t *state) {
  const ldb_comparator_t *ucmp = ldb_user_comparator(db);
  ldb_seqnum_t last_sequence_for_key = LDB_MAX_SEQUENCE;
  int64_t start_micros = ldb_now_usec();
  int64_t imm_micros = 0; /* Micros spent doing db->imm compactions. */
  ldb_buffer_t user_key;
  int has_user_key = 0;
  ldb_stats_t stats;
  ldb_iter_t *input;
  int rc = LDB_OK;
  int which, level;
  ldb_pkey_t ikey;
  char tmp[100];
  size_t i;

  ldb_log(db->options.info_log, "Compacting %d@%d + %d@%d files",
          (int)state->compaction->inputs[0].length,
          state->compaction->level + 0,
          (int)state->compaction->inputs[1].length,
          state->compaction->level + 1);

  ldb_buffer_init(&user_key);
  ldb_stats_init(&stats);

  assert(ldb_versions_files(db->versions, state->compaction->level) > 0);

  assert(state->builder == NULL);
  assert(state->outfile == NULL);

  if (ldb_snaplist_empty(&db->snapshots)) {
    state->smallest_snapshot = db->versions->last_sequence;
  } else {
    state->smallest_snapshot =
      ldb_snaplist_oldest(&db->snapshots)->sequence;
  }

  input = ldb_inputiter_create(db->versions, state->compaction);

  /* Release mutex while we're actually doing the compaction work. */
  ldb_mutex_unlock(&db->mutex);

  ldb_iter_first(input);

  while (ldb_iter_valid(input) && !ldb_atomic_load(&db->shutting_down,
                                                   ldb_order_acquire)) {
    ldb_slice_t key, value;
    int drop = 0;

    /* Prioritize immutable compaction work. */
    if (ldb_atomic_load(&db->has_imm, ldb_order_relaxed)) {
      int64_t imm_start = ldb_now_usec();

      ldb_mutex_lock(&db->mutex);

      if (db->imm != NULL) {
        ldb_compact_memtable(db);

        /* Wake up make_room_for_write() if necessary. */
        ldb_cond_broadcast(&db->background_work_finished_signal);
      }

      ldb_mutex_unlock(&db->mutex);

      imm_micros += (ldb_now_usec() - imm_start);
    }

    key = ldb_iter_key(input);

    if (ldb_compaction_should_stop_before(state->compaction, &key) &&
        state->builder != NULL) {
      rc = ldb_finish_compaction_output_file(db, state, input);

      if (rc != LDB_OK)
        break;
    }

    /* Handle key/value, add to state, etc. */
    if (!ldb_pkey_import(&ikey, &key)) {
      /* Do not hide error keys. */
      ldb_buffer_reset(&user_key);
      has_user_key = 0;
      last_sequence_for_key = LDB_MAX_SEQUENCE;
    } else {
      if (!has_user_key || ldb_compare(ucmp, &ikey.user_key, &user_key) != 0) {
        /* First occurrence of this user key. */
        ldb_buffer_set(&user_key, ikey.user_key.data, ikey.user_key.size);
        has_user_key = 1;
        last_sequence_for_key = LDB_MAX_SEQUENCE;
      }

      if (last_sequence_for_key <= state->smallest_snapshot) {
        /* Hidden by an newer entry for same user key. */
        drop = 1; /* (A) */
      } else if (ikey.type == LDB_TYPE_DELETION &&
                 ikey.sequence <= state->smallest_snapshot &&
                 ldb_compaction_is_base_level_for_key(state->compaction,
                                                      &ikey.user_key)) {
        /* For this user key:
         *
         * (1) there is no data in higher levels
         * (2) data in lower levels will have larger sequence numbers
         * (3) data in layers that are being compacted here and have
         *     smaller sequence numbers will be dropped in the next
         *     few iterations of this loop (by rule (A) above).
         *
         * Therefore this deletion marker is obsolete and can be dropped.
         */
        drop = 1;
      }

      last_sequence_for_key = ikey.sequence;
    }

    if (!drop) {
      /* Open output file if necessary. */
      if (state->builder == NULL) {
        rc = ldb_open_compaction_output_file(db, state);

        if (rc != LDB_OK)
          break;
      }

      if (ldb_tablegen_entries(state->builder) == 0)
        ldb_ikey_copy(&ldb_cstate_top(state)->smallest, &key);

      ldb_ikey_copy(&ldb_cstate_top(state)->largest, &key);

      value = ldb_iter_value(input);

      ldb_tablegen_add(state->builder, &key, &value);

      /* Close output file if it is big enough. */
      if (ldb_tablegen_size(state->builder) >=
          state->compaction->max_output_file_size) {
        rc = ldb_finish_compaction_output_file(db, state, input);

        if (rc != LDB_OK)
          break;
      }
    }

    ldb_iter_next(input);
  }

  if (rc == LDB_OK && ldb_atomic_load(&db->shutting_down, ldb_order_acquire))
    rc = LDB_IOERR; /* "Deleting DB during compaction" */

  if (rc == LDB_OK && state->builder != NULL)
    rc = ldb_finish_compaction_output_file(db, state, input);

  if (rc == LDB_OK)
    rc = ldb_iter_status(input);

  ldb_iter_destroy(input);
  input = NULL;

  stats.micros = ldb_now_usec() - start_micros - imm_micros;

  for (which = 0; which < 2; which++) {
    size_t len = state->compaction->inputs[which].length;

    for (i = 0; i < len; i++) {
      ldb_filemeta_t *f = state->compaction->inputs[which].items[i];

      stats.bytes_read += f->file_size;
    }
  }

  for (i = 0; i < state->outputs.length; i++) {
    ldb_output_t *out = state->outputs.items[i];

    stats.bytes_written += out->file_size;
  }

  ldb_mutex_lock(&db->mutex);

  level = state->compaction->level;

  ldb_stats_add(&db->stats[level + 1], &stats);

  if (rc == LDB_OK)
    rc = ldb_install_compaction_results(db, state);

  if (rc != LDB_OK)
    ldb_record_background_error(db, rc);

  ldb_buffer_clear(&user_key);

  ldb_log(db->options.info_log, "compacted to: %s",
          ldb_versions_summary(db->versions, tmp));

  return rc;
}

static void
ldb_cleanup_compaction(ldb_t *db, ldb_cstate_t *state) {
  size_t i;

  ldb_mutex_assert_held(&db->mutex);

  if (state->builder != NULL) {
    /* May happen if we get a shutdown call in the middle of compaction. */
    ldb_tablegen_abandon(state->builder);
    ldb_tablegen_destroy(state->builder);
  } else {
    assert(state->outfile == NULL);
  }

  if (state->outfile != NULL)
    ldb_wfile_destroy(state->outfile);

  for (i = 0; i < state->outputs.length; i++) {
    const ldb_output_t *out = state->outputs.items[i];

    rb_set64_del(&db->pending_outputs, out->number);
  }

  ldb_cstate_destroy(state);
}

static void
ldb_background_compaction(ldb_t *db) {
  int is_manual = (db->manual_compaction != NULL);
  ldb_compaction_t *c;
  int rc = LDB_OK;

  ldb_mutex_assert_held(&db->mutex);

  if (db->imm != NULL) {
    ldb_compact_memtable(db);
    return;
  }

  if (is_manual) {
    ldb_manual_t *m = db->manual_compaction;

    c = ldb_versions_compact_range(db->versions, m->level, m->begin, m->end);

    m->done = (c == NULL);

    if (c != NULL) {
      ldb_filemeta_t *f = ldb_vector_top(&c->inputs[0]);

      /* Store for later. */
      ldb_ikey_copy(&m->tmp_storage, &f->largest);
    }

    ldb_log(db->options.info_log, "Manual compaction at level-%d", m->level);
  } else {
    c = ldb_versions_pick_compaction(db->versions);
  }

  if (c == NULL) {
    /* Nothing to do. */
  } else if (!is_manual && ldb_compaction_is_trivial_move(c)) {
    /* Move file to next level. */
    ldb_filemeta_t *f;
    char tmp[100];

    assert(c->inputs[0].length == 1);

    f = c->inputs[0].items[0];

    ldb_edit_remove_file(&c->edit, c->level, f->number);

    ldb_edit_add_file(&c->edit, c->level + 1,
                                f->number,
                                f->file_size,
                                &f->smallest,
                                &f->largest);

    rc = ldb_versions_apply(db->versions, &c->edit, &db->mutex);

    if (rc != LDB_OK)
      ldb_record_background_error(db, rc);

    ldb_log(db->options.info_log, "Moved #%lu to level-%d %lu bytes %s: %s",
                                  (unsigned long)f->number,
                                  c->level + 1,
                                  (unsigned long)f->file_size,
                                  ldb_strerror(rc),
                                  ldb_versions_summary(db->versions, tmp));
  } else {
    ldb_cstate_t *state = ldb_cstate_create(c);

    rc = ldb_do_compaction_work(db, state);

    if (rc != LDB_OK)
      ldb_record_background_error(db, rc);

    ldb_cleanup_compaction(db, state);

    ldb_compaction_release_inputs(c);

    ldb_remove_obsolete_files(db);
  }

  if (c != NULL)
    ldb_compaction_destroy(c);

  if (rc == LDB_OK) {
    /* Done. */
  } else if (ldb_atomic_load(&db->shutting_down, ldb_order_acquire)) {
    /* Ignore compaction errors found during shutting down. */
  } else {
    ldb_log(db->options.info_log, "Compaction error: %s", ldb_strerror(rc));
  }

  if (is_manual) {
    ldb_manual_t *m = db->manual_compaction;

    if (rc != LDB_OK)
      m->done = 1;

    if (!m->done) {
      /* We only compacted part of the requested range. Update *m
         to the range that is left to be compacted. */
      m->begin = &m->tmp_storage;
    }

    db->manual_compaction = NULL;
  }
}

static void
ldb_background_call(void *ptr);

static void
ldb_maybe_schedule_compaction(ldb_t *db) {
  ldb_mutex_assert_held(&db->mutex);

  if (db->background_compaction_scheduled) {
    /* Already scheduled. */
  } else if (ldb_atomic_load(&db->shutting_down, ldb_order_acquire)) {
    /* DB is being deleted; no more background compactions. */
  } else if (db->bg_error != LDB_OK) {
    /* Already got an error; no more changes. */
  } else if (db->imm == NULL && db->manual_compaction == NULL &&
             !ldb_versions_needs_compaction(db->versions)) {
    /* No work to be done. */
  } else {
    db->background_compaction_scheduled = 1;
    ldb_pool_schedule(db->pool, &ldb_background_call, db);
  }
}

static void
ldb_background_call(void *ptr) {
  ldb_t *db = ptr;

  ldb_mutex_lock(&db->mutex);

  assert(db->background_compaction_scheduled);

  if (ldb_atomic_load(&db->shutting_down, ldb_order_acquire)) {
    /* No more background work when shutting down. */
  } else if (db->bg_error != LDB_OK) {
    /* No more background work after a background error. */
  } else {
    ldb_background_compaction(db);
  }

  db->background_compaction_scheduled = 0;

  /* Previous compaction may have produced too many files in a level,
     so reschedule another compaction if needed. */
  ldb_maybe_schedule_compaction(db);

  ldb_cond_broadcast(&db->background_work_finished_signal);

  ldb_mutex_unlock(&db->mutex);
}

static void
cleanup_iter_state(void *arg1, void *arg2) {
  ldb_istate_destroy((ldb_istate_t *)arg1);
  (void)arg2;
}

static ldb_iter_t *
ldb_internal_iterator(ldb_t *db, const ldb_readopt_t *options,
                                 ldb_seqnum_t *latest_snapshot,
                                 uint32_t *seed) {
  ldb_iter_t *internal_iter;
  ldb_version_t *current;
  ldb_istate_t *cleanup;
  ldb_vector_t list;

  ldb_vector_init(&list);

  ldb_mutex_lock(&db->mutex);

  *latest_snapshot = db->versions->last_sequence;

  /* Collect together all needed child iterators. */
  ldb_vector_push(&list, ldb_memiter_create(db->mem));
  ldb_memtable_ref(db->mem);

  if (db->imm != NULL) {
    ldb_vector_push(&list, ldb_memiter_create(db->imm));
    ldb_memtable_ref(db->imm);
  }

  current = db->versions->current;

  ldb_version_add_iterators(current, options, &list);

  internal_iter = ldb_mergeiter_create(&db->internal_comparator,
                                       (ldb_iter_t **)list.items,
                                       list.length);

  ldb_version_ref(current);

  cleanup = ldb_istate_create(&db->mutex, db->mem, db->imm,
                              db->versions->current);

  ldb_iter_register_cleanup(internal_iter, cleanup_iter_state, cleanup, NULL);

  *seed = ++db->seed;

  ldb_mutex_unlock(&db->mutex);

  ldb_vector_clear(&list);

  return internal_iter;
}

/* REQUIRES: Writer list must be non-empty. */
/* REQUIRES: First writer must have a non-null batch. */
static ldb_batch_t *
ldb_build_batch_group(ldb_t *db, ldb_waiter_t **last_writer) {
  ldb_waiter_t *first = db->writers.head;
  ldb_batch_t *result = first->batch;
  size_t size, max_size;
  ldb_waiter_t *w;

  ldb_mutex_assert_held(&db->mutex);

  assert(first != NULL);

  result = first->batch;

  assert(result != NULL);

  size = ldb_batch_size(first->batch);

  /* Allow the group to grow up to a maximum size, but if the
     original write is small, limit the growth so we do not slow
     down the small write too much. */
  max_size = 1 << 20;

  if (size <= (128 << 10))
    max_size = size + (128 << 10);

  *last_writer = first;

  /* Advance past "first". */
  for (w = first->next; w != NULL; w = w->next) {
    if (w->sync && !first->sync) {
      /* Do not include a sync write into a
         batch handled by a non-sync write. */
      break;
    }

    if (w->batch != NULL) {
      size += ldb_batch_size(w->batch);

      if (size > max_size) {
        /* Do not make batch too big. */
        break;
      }

      /* Append to *result. */
      if (result == first->batch) {
        /* Switch to temporary batch instead of disturbing caller's batch. */
        result = db->tmp_batch;

        assert(ldb_batch_count(result) == 0);

        ldb_batch_append(result, first->batch);
      }

      ldb_batch_append(result, w->batch);
    }

    *last_writer = w;
  }

  return result;
}

/* REQUIRES: db->mutex is held. */
/* REQUIRES: this thread is currently at the front of the writer queue. */
static int
ldb_make_room_for_write(ldb_t *db, int force) {
  size_t write_buffer_size = db->options.write_buffer_size;
  char fname[LDB_PATH_MAX];
  int allow_delay = !force;
  int rc = LDB_OK;

  ldb_mutex_assert_held(&db->mutex);

  assert(db->writers.length > 0);

  for (;;) {
#define L0_FILES ldb_versions_files(db->versions, 0)
    if (db->bg_error != LDB_OK) {
      /* Yield previous error. */
      rc = db->bg_error;
      break;
    } else if (allow_delay && L0_FILES >= LDB_L0_SLOWDOWN_WRITES_TRIGGER) {
      /* We are getting close to hitting a hard limit on the number of
         L0 files. Rather than delaying a single write by several
         seconds when we hit the hard limit, start delaying each
         individual write by 1ms to reduce latency variance. Also,
         this delay hands over some CPU to the compaction thread in
         case it is sharing the same core as the writer. */
      ldb_mutex_unlock(&db->mutex);
      ldb_sleep_usec(1000);
      allow_delay = 0; /* Do not delay a single write more than once. */
      ldb_mutex_lock(&db->mutex);
    } else if (!force && ldb_memtable_usage(db->mem) <= write_buffer_size) {
      /* There is room in current memtable. */
      break;
    } else if (db->imm != NULL) {
      /* We have filled up the current memtable, but the previous
         one is still being compacted, so we wait. */
      ldb_log(db->options.info_log, "Current memtable full; waiting...");
      ldb_cond_wait(&db->background_work_finished_signal, &db->mutex);
    } else if (L0_FILES >= LDB_L0_STOP_WRITES_TRIGGER) {
      /* There are too many level-0 files. */
      ldb_log(db->options.info_log, "Too many L0 files; waiting...");
      ldb_cond_wait(&db->background_work_finished_signal, &db->mutex);
    } else {
      ldb_wfile_t *lfile = NULL;
      uint64_t new_log_number;

      /* Attempt to switch to a new memtable and trigger compaction of old. */
      assert(db->versions->prev_log_number == 0);

      new_log_number = ldb_versions_new_file_number(db->versions);

      if (!ldb_log_filename(fname, sizeof(fname), db->dbname, new_log_number))
        abort(); /* LCOV_EXCL_LINE */

      rc = ldb_truncfile_create(fname, &lfile);

      if (rc != LDB_OK) {
        /* Avoid chewing through file number space in a tight loop. */
        ldb_versions_reuse_file_number(db->versions, new_log_number);
        break;
      }

      if (db->log != NULL)
        ldb_writer_destroy(db->log);

      if (db->logfile != NULL) {
        rc = ldb_wfile_close(db->logfile);

        if (rc != LDB_OK) {
          /* We may have lost some data written to the previous log file.
           * Switch to the new log file anyway, but record as a background
           * error so we do not attempt any more writes.
           *
           * We could perhaps attempt to save the memtable corresponding
           * to log file and suppress the error if that works, but that
           * would add more complexity in a critical code path.
           */
          ldb_record_background_error(db, rc);
        }

        ldb_wfile_destroy(db->logfile);
      }

      db->logfile = lfile;
      db->logfile_number = new_log_number;
      db->log = ldb_writer_create(lfile, 0);
      db->imm = db->mem;

      ldb_atomic_store(&db->has_imm, 1, ldb_order_release);

      db->mem = ldb_memtable_create(&db->internal_comparator);

      ldb_memtable_ref(db->mem);

      force = 0; /* Do not force another compaction if have room. */
      ldb_maybe_schedule_compaction(db);
    }
#undef L0_FILES
  }

  return rc;
}

static int
ldb_backup_inner(const char *dbname, const char *bakname, rb_set64_t *live) {
  ldb_filelock_t *lock = NULL;
  char lockname[LDB_PATH_MAX];
  char **filenames = NULL;
  char src[LDB_PATH_MAX];
  char dst[LDB_PATH_MAX];
  ldb_filetype_t type;
  uint64_t number;
  int rc = LDB_OK;
  int len = -1;
  int i;

  if (!ldb_lock_filename(lockname, sizeof(lockname), bakname))
    return LDB_INVALID;

  rc = ldb_create_dir(bakname);

  if (rc != LDB_OK)
    return rc;

  rc = ldb_lock_file(lockname, &lock);

  if (rc == LDB_OK) {
    len = ldb_get_children(dbname, &filenames);

    if (len < 0)
      rc = ldb_system_error();
  }

  for (i = 0; i < len && rc == LDB_OK; i++) {
    const char *filename = filenames[i];

    if (!ldb_parse_filename(&type, &number, filename))
      continue;

    if (!ldb_join(src, sizeof(src), dbname, filename)) {
      rc = LDB_INVALID;
      break;
    }

    if (!ldb_join(dst, sizeof(dst), bakname, filename)) {
      rc = LDB_INVALID;
      break;
    }

    switch (type) {
      case LDB_FILE_LOG:
      case LDB_FILE_DESC:
      case LDB_FILE_CURRENT:
        rc = ldb_copy_file(src, dst);
        break;
      case LDB_FILE_TABLE:
        if (live == NULL || rb_set64_has(live, number))
          rc = ldb_link_file(src, dst);
        break;
      case LDB_FILE_TEMP:
      case LDB_FILE_LOCK:
        break;
      case LDB_FILE_INFO:
        if (live == NULL)
          rc = ldb_copy_file(src, dst);
        break;
    }
  }

  if (len >= 0)
    ldb_free_children(filenames, len);

  if (rc != LDB_OK) {
    len = ldb_get_children(bakname, &filenames);

    for (i = 0; i < len; i++) {
      const char *filename = filenames[i];

      if (!ldb_parse_filename(&type, &number, filename))
        continue;

      if (type == LDB_FILE_LOCK)
        continue; /* Lock file will be deleted at end. */

      if (!ldb_join(dst, sizeof(dst), bakname, filename))
        continue;

      ldb_remove_file(dst);
    }

    if (len >= 0)
      ldb_free_children(filenames, len);
  }

  if (lock != NULL) {
    ldb_unlock_file(lock);
    ldb_remove_file(lockname);
  }

  if (rc == LDB_OK)
    rc = ldb_sync_dir(bakname);
  else
    ldb_remove_dir(bakname);

  return rc;
}

/*
 * API
 */

int
ldb_open(const char *dbname, const ldb_dbopt_t *options, ldb_t **dbptr) {
  char path[LDB_PATH_MAX];
  int save_manifest = 0;
  ldb_edit_t edit;
  int rc = LDB_OK;
  ldb_t *db;

  ldb_crc32c_init();

  *dbptr = NULL;

  if (options == NULL)
    return LDB_INVALID;

  if (options->filter_policy != NULL) {
    if (strlen(options->filter_policy->name) > 64)
      return LDB_INVALID;
  }

  if (!ldb_path_absolute(path, sizeof(path) - 35, dbname))
    return LDB_INVALID;

  db = ldb_create(path, options);

  ldb_edit_init(&edit);
  ldb_mutex_lock(&db->mutex);

  /* Recover handles create_if_missing, error_if_exists. */
  rc = ldb_recover(db, &edit, &save_manifest);

  if (rc == LDB_OK && db->mem == NULL) {
    /* Create new log and a corresponding memtable. */
    uint64_t new_log_number = ldb_versions_new_file_number(db->versions);
    ldb_wfile_t *lfile;

    if (!ldb_log_filename(path, sizeof(path), db->dbname, new_log_number))
      abort(); /* LCOV_EXCL_LINE */

    rc = ldb_truncfile_create(path, &lfile);

    if (rc == LDB_OK) {
      ldb_edit_set_log_number(&edit, new_log_number);

      db->logfile = lfile;
      db->logfile_number = new_log_number;
      db->log = ldb_writer_create(lfile, 0);
      db->mem = ldb_memtable_create(&db->internal_comparator);

      ldb_memtable_ref(db->mem);
    }
  }

  if (rc == LDB_OK && save_manifest) {
    ldb_edit_set_prev_log_number(&edit, 0); /* No older logs needed
                                               after recovery. */
    ldb_edit_set_log_number(&edit, db->logfile_number);

    rc = ldb_versions_apply(db->versions, &edit, &db->mutex);
  }

  if (rc == LDB_OK) {
    ldb_remove_obsolete_files(db);
    ldb_maybe_schedule_compaction(db);
  }

  ldb_mutex_unlock(&db->mutex);

  if (rc == LDB_OK) {
    assert(db->mem != NULL);
    *dbptr = db;
  } else {
    ldb_destroy_internal(db);
  }

  ldb_edit_clear(&edit);

  return rc;
}

void
ldb_close(ldb_t *db) {
  ldb_destroy_internal(db);
}

int
ldb_get(ldb_t *db, const ldb_slice_t *key,
                   ldb_slice_t *value,
                   const ldb_readopt_t *options) {
  ldb_memtable_t *mem, *imm;
  ldb_version_t *current;
  ldb_seqnum_t snapshot;
  int have_stat_update = 0;
  ldb_getstats_t stats;
  int rc = LDB_OK;

  if (value != NULL)
    ldb_buffer_init(value);

  if (options == NULL)
    options = ldb_readopt_default;

  ldb_mutex_lock(&db->mutex);

  if (options->snapshot != NULL)
    snapshot = options->snapshot->sequence;
  else
    snapshot = db->versions->last_sequence;

  mem = db->mem;
  imm = db->imm;
  current = db->versions->current;

  ldb_memtable_ref(mem);

  if (imm != NULL)
    ldb_memtable_ref(imm);

  ldb_version_ref(current);

  /* Unlock while reading from files and memtables. */
  {
    ldb_lkey_t lkey;

    ldb_mutex_unlock(&db->mutex);

    /* First look in the memtable, then in the immutable memtable (if any). */
    ldb_lkey_init(&lkey, key, snapshot);

    if (ldb_memtable_get(mem, &lkey, value, &rc)) {
      /* Done. */
    } else if (imm != NULL && ldb_memtable_get(imm, &lkey, value, &rc)) {
      /* Done. */
    } else {
      rc = ldb_version_get(current, options, &lkey, value, &stats);
      have_stat_update = 1;
    }

    ldb_lkey_clear(&lkey);

    ldb_mutex_lock(&db->mutex);
  }

  if (have_stat_update && ldb_version_update_stats(current, &stats))
    ldb_maybe_schedule_compaction(db);

  ldb_memtable_unref(mem);

  if (imm != NULL)
    ldb_memtable_unref(imm);

  ldb_version_unref(current);

  ldb_mutex_unlock(&db->mutex);

  if (value != NULL) {
    if (rc == LDB_OK)
      ldb_buffer_grow(value, 1);
    else
      ldb_buffer_clear(value);
  }

  return rc;
}

int
ldb_has(ldb_t *db, const ldb_slice_t *key, const ldb_readopt_t *options) {
  return ldb_get(db, key, NULL, options);
}

int
ldb_put(ldb_t *db, const ldb_slice_t *key,
                   const ldb_slice_t *value,
                   const ldb_writeopt_t *options) {
  ldb_batch_t batch;
  int rc;

  ldb_batch_init(&batch);
  ldb_batch_put(&batch, key, value);

  rc = ldb_write(db, &batch, options);

  ldb_batch_clear(&batch);

  return rc;
}

int
ldb_del(ldb_t *db, const ldb_slice_t *key, const ldb_writeopt_t *options) {
  ldb_batch_t batch;
  int rc;

  ldb_batch_init(&batch);
  ldb_batch_del(&batch, key);

  rc = ldb_write(db, &batch, options);

  ldb_batch_clear(&batch);

  return rc;
}

int
ldb_write(ldb_t *db, ldb_batch_t *updates, const ldb_writeopt_t *options) {
  ldb_waiter_t *last_writer;
  uint64_t last_sequence;
  ldb_waiter_t w;
  int rc;

  if (options == NULL)
    options = ldb_writeopt_default;

  ldb_waiter_init(&w);

  w.batch = updates;
  w.sync = options->sync;
  w.done = 0;

  ldb_mutex_lock(&db->mutex);

  ldb_queue_push(&db->writers, &w);

  while (!w.done && &w != db->writers.head)
    ldb_cond_wait(&w.cv, &db->mutex);

  if (w.done) {
    ldb_mutex_unlock(&db->mutex);
    ldb_waiter_clear(&w);
    return w.status;
  }

  /* May temporarily unlock and wait. */
  rc = ldb_make_room_for_write(db, updates == NULL);
  last_sequence = db->versions->last_sequence;
  last_writer = &w;

  if (rc == LDB_OK && updates != NULL) { /* NULL batch is for compactions. */
    ldb_batch_t *write_batch = ldb_build_batch_group(db, &last_writer);

    ldb_batch_set_sequence(write_batch, last_sequence + 1);

    last_sequence += ldb_batch_count(write_batch);

    /* Add to log and apply to memtable. We can release the lock
       during this phase since &w is currently responsible for logging
       and protects against concurrent loggers and concurrent writes
       into db->mem. */
    {
      ldb_slice_t contents;
      int sync_error = 0;

      ldb_mutex_unlock(&db->mutex);

      contents = ldb_batch_contents(write_batch);

      rc = ldb_writer_add_record(db->log, &contents);

      if (rc == LDB_OK && options->sync) {
        rc = ldb_wfile_sync(db->logfile);

        if (rc != LDB_OK)
          sync_error = 1;
      }

      if (rc == LDB_OK)
        rc = ldb_batch_insert_into(write_batch, db->mem);

      ldb_mutex_lock(&db->mutex);

      if (sync_error) {
        /* The state of the log file is indeterminate: the log record we
           just added may or may not show up when the DB is re-opened.
           So we force the DB into a mode where all future writes fail. */
        ldb_record_background_error(db, rc);
      }
    }

    if (write_batch == db->tmp_batch)
      ldb_batch_reset(db->tmp_batch);

    assert(last_sequence >= db->versions->last_sequence);

    db->versions->last_sequence = last_sequence;
  }

  for (;;) {
    ldb_waiter_t *ready = ldb_queue_shift(&db->writers);

    if (ready != &w) {
      ready->status = rc;
      ready->done = 1;
      ldb_cond_signal(&ready->cv);
    }

    if (ready == last_writer)
      break;
  }

  /* Notify new head of write queue. */
  if (db->writers.length > 0)
    ldb_cond_signal(&db->writers.head->cv);

  ldb_mutex_unlock(&db->mutex);
  ldb_waiter_clear(&w);

  return rc;
}

const ldb_snapshot_t *
ldb_snapshot(ldb_t *db) {
  ldb_snapshot_t *snap;
  ldb_seqnum_t seq;

  ldb_mutex_lock(&db->mutex);

  seq = db->versions->last_sequence;
  snap = ldb_snaplist_new(&db->snapshots, seq);

  ldb_mutex_unlock(&db->mutex);

  return snap;
}

void
ldb_release(ldb_t *db, const ldb_snapshot_t *snapshot) {
  ldb_mutex_lock(&db->mutex);

  ldb_snaplist_delete(&db->snapshots, snapshot);

  ldb_mutex_unlock(&db->mutex);
}

ldb_iter_t *
ldb_iterator(ldb_t *db, const ldb_readopt_t *options) {
  const ldb_comparator_t *ucmp = ldb_user_comparator(db);
  ldb_seqnum_t latest_snapshot;
  ldb_iter_t *iter;
  uint32_t seed;

  if (options == NULL)
    options = ldb_iteropt_default;

  iter = ldb_internal_iterator(db, options, &latest_snapshot, &seed);

  return ldb_dbiter_create(db, ucmp, iter,
                           (options->snapshot != NULL
                              ? options->snapshot->sequence
                              : latest_snapshot),
                           seed);
}

int
ldb_property(ldb_t *db, const char *property, char **value) {
  const char *in = property;

  *value = NULL;

  if (!ldb_starts_with(in, "leveldb."))
    return 0;

  in += 8;

  ldb_mutex_lock(&db->mutex);

  if (ldb_starts_with(in, "num-files-at-level")) {
    uint64_t level;
    int ok;

    in += 18;

    ok = ldb_decode_int(&level, &in) && *in == 0;

    if (!ok || level >= LDB_NUM_LEVELS) {
      ldb_mutex_unlock(&db->mutex);
      return 0;
    }

    *value = ldb_malloc(21);

    ldb_encode_int(*value, ldb_versions_files(db->versions, level), 0);

    ldb_mutex_unlock(&db->mutex);

    return 1;
  }

  if (strcmp(in, "stats") == 0) {
    ldb_buffer_t val;
    char buf[200];
    int level;

    ldb_buffer_init(&val);

    sprintf(buf, "                               Compactions\n"
                 "Level  Files Size(MB) Time(sec) Read(MB) Write(MB)\n"
                 "--------------------------------------------------\n");

    ldb_buffer_string(&val, buf);

    for (level = 0; level < LDB_NUM_LEVELS; level++) {
      int files = ldb_versions_files(db->versions, level);
      ldb_stats_t *stats = &db->stats[level];

      if (stats->micros > 0 || files > 0) {
        int64_t bytes = ldb_versions_bytes(db->versions, level);

        sprintf(buf, "%3d %8d %8.0f %9.0f %8.0f %9.0f\n",
                     level, files, bytes / 1048576.0,
                     stats->micros / 1e6,
                     stats->bytes_read / 1048576.0,
                     stats->bytes_written / 1048576.0);

        ldb_buffer_string(&val, buf);
      }
    }

    ldb_buffer_push(&val, 0);

    *value = (char *)val.data;

    ldb_mutex_unlock(&db->mutex);

    return 1;
  }

  if (strcmp(in, "sstables") == 0) {
    ldb_buffer_t val;

    ldb_buffer_init(&val);
    ldb_version_debug(&val, db->versions->current);
    ldb_buffer_push(&val, 0);

    *value = (char *)val.data;

    ldb_mutex_unlock(&db->mutex);

    return 1;
  }

  if (strcmp(in, "approximate-memory-usage") == 0) {
    size_t total_usage = ldb_lru_usage(db->options.block_cache);

    if (db->mem != NULL)
      total_usage += ldb_memtable_usage(db->mem);

    if (db->imm != NULL)
      total_usage += ldb_memtable_usage(db->imm);

    *value = ldb_malloc(21);

    ldb_encode_int(*value, total_usage, 0);

    ldb_mutex_unlock(&db->mutex);

    return 1;
  }

  ldb_mutex_unlock(&db->mutex);

  return 0;
}

void
ldb_approximate_sizes(ldb_t *db, const ldb_range_t *range,
                                 size_t length,
                                 uint64_t *sizes) {
  uint64_t start, limit;
  ldb_ikey_t k1, k2;
  ldb_version_t *v;
  size_t i;

  ldb_mutex_lock(&db->mutex);

  v = db->versions->current;

  ldb_version_ref(v);

  ldb_ikey_init(&k1);
  ldb_ikey_init(&k2);

  for (i = 0; i < length; i++) {
    /* Convert user_key into a corresponding internal key. */
    ldb_ikey_set(&k1, &range[i].start, LDB_MAX_SEQUENCE, LDB_VALTYPE_SEEK);
    ldb_ikey_set(&k2, &range[i].limit, LDB_MAX_SEQUENCE, LDB_VALTYPE_SEEK);

    start = ldb_versions_approximate_offset(db->versions, v, &k1);
    limit = ldb_versions_approximate_offset(db->versions, v, &k2);

    sizes[i] = (limit >= start ? limit - start : 0);
  }

  ldb_ikey_clear(&k1);
  ldb_ikey_clear(&k2);

  ldb_version_unref(v);

  ldb_mutex_unlock(&db->mutex);
}

void
ldb_compact(ldb_t *db, const ldb_slice_t *begin, const ldb_slice_t *end) {
  int max_level_with_files = 1;
  int level;

  {
    ldb_version_t *base;

    ldb_mutex_lock(&db->mutex);

    base = db->versions->current;

    for (level = 1; level < LDB_NUM_LEVELS; level++) {
      if (ldb_version_overlap_in_level(base, level, begin, end))
        max_level_with_files = level;
    }

    ldb_mutex_unlock(&db->mutex);
  }

  ldb_test_compact_memtable(db);

  for (level = 0; level < max_level_with_files; level++)
    ldb_test_compact_range(db, level, begin, end);
}

int
ldb_backup(ldb_t *db, const char *name) {
  rb_set64_t live;
  int rc;

  if (strlen(name) + 1 > LDB_PATH_MAX - 35)
    return LDB_INVALID;

  ldb_mutex_lock(&db->mutex);

  while (db->background_compaction_scheduled)
    ldb_cond_wait(&db->background_work_finished_signal, &db->mutex);

  rc = db->bg_error;

  if (rc == LDB_OK) {
    rb_set64_init(&live);

    ldb_versions_add_files(db->versions, &live);

    rc = ldb_backup_inner(db->dbname, name, &live);

    rb_set64_clear(&live);
  }

  ldb_mutex_unlock(&db->mutex);

  return rc;
}

#undef ldb_compare

int
ldb_compare(const ldb_t *db, const ldb_slice_t *x, const ldb_slice_t *y) {
  const ldb_comparator_t *cmp = ldb_user_comparator(db);
  return cmp->compare(cmp, x, y);
}

#define ldb_compare ldb_compare_internal

/*
 * Static
 */

int
ldb_copy(const char *from, const char *to, const ldb_dbopt_t *options) {
  char path[LDB_PATH_MAX];
  ldb_filelock_t *lock;
  int rc;

  (void)options;

  if (strlen(from) + 1 > LDB_PATH_MAX - 35)
    return LDB_INVALID;

  if (strlen(to) + 1 > LDB_PATH_MAX - 35)
    return LDB_INVALID;

  if (!ldb_current_filename(path, sizeof(path), from))
    return LDB_INVALID;

  if (!ldb_file_exists(path))
    return LDB_ENOENT;

  if (!ldb_lock_filename(path, sizeof(path), from))
    return LDB_INVALID;

  rc = ldb_lock_file(path, &lock);

  if (rc == LDB_OK) {
    rc = ldb_backup_inner(from, to, NULL);

    ldb_unlock_file(lock);
  }

  return rc;
}

int
ldb_destroy(const char *dbname, const ldb_dbopt_t *options) {
  char lockname[LDB_PATH_MAX];
  char subdir[LDB_PATH_MAX];
  char path[LDB_PATH_MAX];
  ldb_filelock_t *lock;
  char **files = NULL;
  int rc = LDB_OK;
  int len;

  (void)options;

  if (strlen(dbname) + 1 > LDB_PATH_MAX - 35)
    return LDB_INVALID;

  if (!ldb_lock_filename(lockname, sizeof(lockname), dbname))
    return LDB_INVALID;

  if (!ldb_join(subdir, sizeof(subdir), dbname, "lost"))
    return LDB_INVALID;

  len = ldb_get_children(dbname, &files);

  if (len < 0) {
    /* Ignore error in case directory does not exist. */
    rc = ldb_system_error();

    if (rc == LDB_ENOENT)
      return LDB_OK;

    return rc;
  }

  rc = ldb_lock_file(lockname, &lock);

  if (rc == LDB_OK) {
    ldb_filetype_t type;
    uint64_t number;
    int i, status;

    for (i = 0; i < len; i++) {
      const char *name = files[i];

      if (!ldb_parse_filename(&type, &number, name))
        continue;

      if (type == LDB_FILE_LOCK)
        continue; /* Lock file will be deleted at end. */

      if (!ldb_join(path, sizeof(path), dbname, name)) {
        rc = LDB_INVALID;
        continue;
      }

      status = ldb_remove_file(path);

      if (rc == LDB_OK && status != LDB_OK)
        rc = status;
    }

    if (ldb_current_filename(path, sizeof(path), subdir) &&
        !ldb_file_exists(path)) {
      char **subfiles = NULL;
      int sublen = ldb_get_children(subdir, &subfiles);

      for (i = 0; i < sublen; i++) {
        const char *name = subfiles[i];

        if (!ldb_parse_filename(&type, &number, name))
          continue;

        if (!ldb_join(path, sizeof(path), subdir, name)) {
          rc = LDB_INVALID;
          continue;
        }

        status = ldb_remove_file(path);

        if (rc == LDB_OK && status != LDB_OK)
          rc = status;
      }

      if (sublen >= 0) {
        ldb_free_children(subfiles, sublen);
        ldb_remove_dir(subdir);
      }
    }

    ldb_unlock_file(lock); /* Ignore error since state is already gone. */
    ldb_remove_file(lockname);
    ldb_remove_dir(dbname); /* Ignore error in case dir contains other files. */
  }

  ldb_free_children(files, len);

  return rc;
}

/*
 * Testing
 */

int
ldb_test_compact_memtable(ldb_t *db) {
  /* NULL batch means just wait for earlier writes to be done. */
  int rc = ldb_write(db, NULL, ldb_writeopt_default);

  if (rc == LDB_OK) {
    /* Wait until the compaction completes. */
    ldb_mutex_lock(&db->mutex);

    while (db->imm != NULL && db->bg_error == LDB_OK)
      ldb_cond_wait(&db->background_work_finished_signal, &db->mutex);

    if (db->imm != NULL)
      rc = db->bg_error;

    ldb_mutex_unlock(&db->mutex);
  }

  return rc;
}

void
ldb_test_compact_range(ldb_t *db, int level,
                                  const ldb_slice_t *begin,
                                  const ldb_slice_t *end) {
  ldb_ikey_t begin_storage, end_storage;
  ldb_manual_t manual;

  assert(level >= 0);
  assert(level + 1 < LDB_NUM_LEVELS);

  ldb_manual_init(&manual, level);

  if (begin == NULL) {
    manual.begin = NULL;
  } else {
    ldb_ikey_init(&begin_storage);
    ldb_ikey_set(&begin_storage, begin, LDB_MAX_SEQUENCE, LDB_VALTYPE_SEEK);
    manual.begin = &begin_storage;
  }

  if (end == NULL) {
    manual.end = NULL;
  } else {
    ldb_ikey_init(&end_storage);
    ldb_ikey_set(&end_storage, end, 0, (ldb_valtype_t)0);
    manual.end = &end_storage;
  }

  ldb_mutex_lock(&db->mutex);

  while (!manual.done &&
         !ldb_atomic_load(&db->shutting_down, ldb_order_acquire) &&
         db->bg_error == LDB_OK) {
    if (db->manual_compaction == NULL) { /* Idle. */
      db->manual_compaction = &manual;
      ldb_maybe_schedule_compaction(db);
    } else { /* Running either my compaction or another compaction. */
      ldb_cond_wait(&db->background_work_finished_signal, &db->mutex);
    }
  }

  if (db->manual_compaction == &manual) {
    /* Cancel my manual compaction since we aborted early for some reason. */
    db->manual_compaction = NULL;
  }

  ldb_mutex_unlock(&db->mutex);

  if (begin != NULL)
    ldb_ikey_clear(&begin_storage);

  if (end != NULL)
    ldb_ikey_clear(&end_storage);

  ldb_manual_clear(&manual);
}

ldb_iter_t *
ldb_test_internal_iterator(ldb_t *db) {
  ldb_seqnum_t ignored;
  uint32_t ignored_seed;

  return ldb_internal_iterator(db, ldb_readopt_default,
                                   &ignored,
                                   &ignored_seed);
}

int64_t
ldb_test_max_next_level_overlapping_bytes(ldb_t *db) {
  int64_t result;
  ldb_mutex_lock(&db->mutex);
  result = ldb_versions_max_next_level_overlapping_bytes(db->versions);
  ldb_mutex_unlock(&db->mutex);
  return result;
}

/*
 * Internal
 */

void
ldb_record_read_sample(ldb_t *db, const ldb_slice_t *key) {
  ldb_version_t *current;

  ldb_mutex_lock(&db->mutex);

  current = db->versions->current;

  if (ldb_version_record_read_sample(current, key))
    ldb_maybe_schedule_compaction(db);

  ldb_mutex_unlock(&db->mutex);
}
