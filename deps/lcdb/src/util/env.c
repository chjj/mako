/*!
 * env.c - platform-specific functions for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on google/leveldb:
 *   Copyright (c) 2011, The LevelDB Authors. All rights reserved.
 *   https://github.com/google/leveldb
 *
 * See LICENSE for more information.
 */

#if defined(LDB_MEMENV)
#  include "env_mem_impl.h"
#elif defined(_WIN32)
#  include "env_win_impl.h"
#else
#  include "env_unix_impl.h"
#endif

/*
 * Globals
 */

#ifndef NDEBUG
struct ldb_env_state_s ldb_env_state = {
  /* .enable_testing = */ 0,
  /* .delay_data_sync = */ 0,
  /* .data_sync_error = */ 0,
  /* .no_space = */ 0,
  /* .non_writable = */ 0,
  /* .manifest_sync_error = */ 0,
  /* .manifest_write_error = */ 0,
  /* .count_random_reads = */ 0,
  /* .random_read_counter = */ 0,
  /* .writable_file_error = */ 0,
  /* .num_writable_file_errors = */ 0
};
#endif

/*
 * Environment
 */

int
ldb_rfile_pread(ldb_rfile_t *file,
                ldb_slice_t *result,
                void *buf,
                size_t count,
                uint64_t offset) {
#ifndef NDEBUG
  struct ldb_env_state_s *state = &ldb_env_state;

  if (state->enable_testing && state->count_random_reads) {
    ldb_atomic_fetch_add(&state->random_read_counter, 1,
                         ldb_order_seq_cst);
  }
#endif

  return ldb_rfile_pread0(file, result, buf, count, offset);
}

int
ldb_wfile_append(ldb_wfile_t *file, const ldb_slice_t *data) {
#ifndef NDEBUG
  struct ldb_env_state_s *state = &ldb_env_state;

  if (state->enable_testing) {
    if (file->manifest) {
      if (ldb_atomic_load(&state->manifest_write_error, ldb_order_acquire))
        return LDB_IOERR; /* "simulated writer error" */
    } else {
      if (ldb_atomic_load(&state->no_space, ldb_order_acquire))
        return LDB_OK; /* Drop writes on the floor. */
    }
  }
#endif

  return ldb_wfile_append0(file, data);
}

int
ldb_wfile_sync(ldb_wfile_t *file) {
#ifndef NDEBUG
  struct ldb_env_state_s *state = &ldb_env_state;

  if (state->enable_testing) {
    if (file->manifest) {
      if (ldb_atomic_load(&state->manifest_sync_error, ldb_order_acquire))
        return LDB_IOERR; /* "simulated sync error" */
    } else {
      if (ldb_atomic_load(&state->data_sync_error, ldb_order_acquire))
        return LDB_IOERR; /* "simulated data sync error" */

#if defined(_WIN32) || defined(LDB_PTHREAD)
      while (ldb_atomic_load(&state->delay_data_sync, ldb_order_acquire))
        ldb_sleep_usec(100000);
#endif
    }
  }
#endif

  return ldb_wfile_sync0(file);
}

int
ldb_truncfile_create(const char *filename, ldb_wfile_t **file) {
#ifndef NDEBUG
  struct ldb_env_state_s *state = &ldb_env_state;

  if (state->enable_testing) {
    if (ldb_atomic_load(&state->non_writable, ldb_order_acquire))
      return LDB_IOERR; /* "simulated write error" */

    if (state->writable_file_error) {
      ++state->num_writable_file_errors;
      return LDB_IOERR; /* "fake error" */
    }
  }
#endif

  return ldb_truncfile_create0(filename, file);
}

int
ldb_appendfile_create(const char *filename, ldb_wfile_t **file) {
#ifndef NDEBUG
  struct ldb_env_state_s *state = &ldb_env_state;

  if (state->enable_testing) {
    if (state->writable_file_error) {
      ++state->num_writable_file_errors;
      return LDB_IOERR; /* "fake error" */
    }
  }
#endif

  return ldb_appendfile_create0(filename, file);
}

int
ldb_write_file(const char *fname, const ldb_slice_t *data, int should_sync) {
  ldb_wfile_t *file = NULL;
  int rc;

  if ((rc = ldb_truncfile_create(fname, &file)))
    return rc;

  rc = ldb_wfile_append(file, data);

  if (rc == LDB_OK && should_sync)
    rc = ldb_wfile_sync(file);

  if (rc == LDB_OK)
    rc = ldb_wfile_close(file);

  ldb_wfile_destroy(file);

  if (rc != LDB_OK)
    ldb_remove_file(fname);

  return rc;
}

int
ldb_read_file(const char *fname, ldb_buffer_t *data) {
  ldb_rfile_t *file;
  ldb_slice_t chunk;
  char space[8192];
  int rc;

  if ((rc = ldb_seqfile_create(fname, &file)))
    return rc;

  ldb_buffer_reset(data);

  for (;;) {
    rc = ldb_rfile_read(file, &chunk, space, sizeof(space));

    if (rc != LDB_OK)
      break;

    if (chunk.size == 0)
      break;

    ldb_buffer_append(data, chunk.data, chunk.size);
  }

  ldb_rfile_destroy(file);

  return rc;
}

int
ldb_test_filename(char *result, size_t size, const char *name) {
  if (!ldb_test_directory(result, size))
    return 0;

  return ldb_join(result, size, result, name);
}
