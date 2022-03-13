/*!
 * env_mem_impl.h - memory environment for lcdb
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
#include <time.h>

#if defined(_WIN32)
#  include <windows.h>
#else /* !_WIN32 */
#  include <sys/types.h>
#  include <sys/time.h>
#  if !defined(FD_SETSIZE) && !defined(FD_SET)
#    include <sys/select.h>
#  endif
#endif /* !_WIN32 */

#include "env.h"
#include "internal.h"
#include "port.h"
#include "rbt.h"
#include "slice.h"
#include "status.h"
#include "vector.h"

/*
 * Types
 */

typedef struct ldb_fstate_s ldb_fstate_t;

struct ldb_filelock_s {
  char path[LDB_PATH_MAX];
};

/*
 * Globals
 */

static ldb_mutex_t file_mutex = LDB_MUTEX_INITIALIZER;
static rb_map_t file_map_;
static rb_set_t file_set;

/*
 * Helpers
 */

static char *
ldb_strdup(const char *xp) {
  size_t xn = strlen(xp);
  return memcpy(ldb_malloc(xn + 1), xp, xn + 1);
}

/*
 * File State
 */

static const int k_block_size = 8 * 1024;

struct ldb_fstate_s {
  char path[LDB_PATH_MAX];
  ldb_mutex_t refs_mutex;
  ldb_mutex_t blocks_mutex;
  ldb_vector_t blocks;
  uint64_t size;
  int refs;
};

static ldb_fstate_t *
ldb_fstate_create(const char *path) {
  ldb_fstate_t *state = ldb_malloc(sizeof(ldb_fstate_t));

  strcpy(state->path, path);

  ldb_mutex_init(&state->refs_mutex);
  ldb_mutex_init(&state->blocks_mutex);
  ldb_vector_init(&state->blocks);

  state->size = 0;
  state->refs = 0;

  return state;
}

static void
ldb_fstate_truncate(ldb_fstate_t *state) {
  size_t i;

  ldb_mutex_lock(&state->blocks_mutex);

  for (i = 0; i < state->blocks.length; i++)
    ldb_free(state->blocks.items[i]);

  state->blocks.length = 0;
  state->size = 0;

  ldb_mutex_unlock(&state->blocks_mutex);
}

static void
ldb_fstate_destroy(ldb_fstate_t *state) {
  ldb_fstate_truncate(state);
  ldb_mutex_destroy(&state->refs_mutex);
  ldb_mutex_destroy(&state->blocks_mutex);
  ldb_vector_clear(&state->blocks);
  ldb_free(state);
}

static ldb_fstate_t *
ldb_fstate_ref(ldb_fstate_t *state) {
  ldb_mutex_lock(&state->refs_mutex);
  ++state->refs;
  ldb_mutex_unlock(&state->refs_mutex);
  return state;
}

static void
ldb_fstate_unref(ldb_fstate_t *state) {
  int do_delete = 0;

  ldb_mutex_lock(&state->refs_mutex);

  --state->refs;

  assert(state->refs >= 0);

  if (state->refs <= 0)
    do_delete = 1;

  ldb_mutex_unlock(&state->refs_mutex);

  if (do_delete)
    ldb_fstate_destroy(state);
}

static uint64_t
ldb_fstate_size(const ldb_fstate_t *state) {
  ldb_mutex_t *mutex = (ldb_mutex_t *)&state->blocks_mutex;
  uint64_t size;

  ldb_mutex_lock(mutex);

  size = state->size;

  ldb_mutex_unlock(mutex);

  return size;
}

static int
ldb_fstate_pread(const ldb_fstate_t *state,
                 ldb_slice_t *result,
                 void *buf,
                 size_t count,
                 uint64_t offset) {
  ldb_mutex_t *mutex = (ldb_mutex_t *)&state->blocks_mutex;
  size_t block, block_offset, bytes_to_copy;
  uint64_t available;
  unsigned char *dst;

  ldb_mutex_lock(mutex);

  if (offset > state->size) {
    ldb_mutex_unlock(mutex);
    return LDB_IOERR; /* "Offset greater than file size." */
  }

  available = state->size - offset;

  if (count > available)
    count = (size_t)available;

  if (count == 0) {
    ldb_mutex_unlock(mutex);
    *result = ldb_slice(0, 0);
    return LDB_OK;
  }

  assert(offset / k_block_size <= (size_t)-1);

  block = (size_t)(offset / k_block_size);
  block_offset = offset % k_block_size;
  bytes_to_copy = count;
  dst = buf;

  while (bytes_to_copy > 0) {
    size_t avail = k_block_size - block_offset;

    if (avail > bytes_to_copy)
      avail = bytes_to_copy;

    memcpy(dst, (char *)state->blocks.items[block] + block_offset, avail);

    bytes_to_copy -= avail;
    dst += avail;
    block++;
    block_offset = 0;
  }

  ldb_mutex_unlock(mutex);

  *result = ldb_slice(buf, count);

  return LDB_OK;
}

static int
ldb_fstate_append(ldb_fstate_t *state, const ldb_slice_t *data) {
  unsigned const char *src = data->data;
  size_t src_len = data->size;

  ldb_mutex_lock(&state->blocks_mutex);

  while (src_len > 0) {
    size_t offset = state->size % k_block_size;
    size_t avail;

    if (offset != 0) {
      /* There is some room in the last block. */
      avail = k_block_size - offset;
    } else {
      /* No room in the last block; push new one. */
      ldb_vector_push(&state->blocks, ldb_malloc(k_block_size));
      avail = k_block_size;
    }

    if (avail > src_len)
      avail = src_len;

    memcpy((char *)ldb_vector_top(&state->blocks) + offset, src, avail);

    src_len -= avail;
    src += avail;
    state->size += avail;
  }

  ldb_mutex_unlock(&state->blocks_mutex);

  return LDB_OK;
}

/*
 * Environment
 */

static int
by_string(rb_val_t x, rb_val_t y, void *arg) {
  (void)arg;
  return strcmp(x.p, y.p);
}

static rb_map_t *
ensure_map(void) {
  if (file_map_.root == NULL)
    rb_map_init(&file_map_, by_string, NULL);

  return &file_map_;
}

#define file_map (*ensure_map())

/*
 * Filesystem
 */

int
ldb_path_absolute(char *buf, size_t size, const char *name) {
  size_t len = strlen(name);

  if (len == 0 || len + 1 > size)
    return 0;

  memcpy(buf, name, len + 1);

#ifdef _WIN32
  {
    size_t i;

    for (i = 0; i < len; i++) {
      if (buf[i] == '/')
        buf[i] = '\\';
    }
  }
#endif

  return 1;
}

int
ldb_file_exists(const char *filename) {
  int result;
  ldb_mutex_lock(&file_mutex);
  result = rb_map_has(&file_map, filename);
  ldb_mutex_unlock(&file_mutex);
  return result;
}

int
ldb_get_children(const char *path, char ***out) {
  size_t plen = strlen(path);
  ldb_vector_t names;
  void *key;

#if defined(_WIN32)
  while (plen > 0 && (path[plen - 1] == '/' || path[plen - 1] == '\\')
    plen -= 1;
#else
  while (plen > 0 && path[plen - 1] == '/')
    plen -= 1;
#endif

  ldb_vector_init(&names);
  ldb_vector_grow(&names, 1);

  ldb_mutex_lock(&file_mutex);

  rb_map_keys(&file_map, key) {
    const char *name = key;
    size_t nlen = strlen(name);

#if defined(_WIN32)
    if (nlen > plen + 1 && (name[plen] == '/' || name[plen] == '\\'))
#else
    if (nlen > plen + 1 && name[plen] == '/')
#endif
    {
      if (memcmp(name, path, plen) == 0)
        ldb_vector_push(&names, ldb_strdup(name + plen + 1));
    }
  }

  ldb_mutex_unlock(&file_mutex);

  *out = (char **)names.items;

  return names.length;
}

void
ldb_free_children(char **list, int len) {
  int i;

  for (i = 0; i < len; i++)
    ldb_free(list[i]);

  ldb_free(list);
}

static int
ldb_delete_file(const char *filename) {
  rb_node_t *node = rb_map_del(&file_map, filename);

  if (node != NULL) {
    ldb_fstate_unref(node->value.p);
    rb_node_destroy(node);
    return 1;
  }

  return 0;
}

int
ldb_remove_file(const char *filename) {
  int result;

  ldb_mutex_lock(&file_mutex);

  result = ldb_delete_file(filename);

  ldb_mutex_unlock(&file_mutex);

  return result ? LDB_OK : LDB_NOTFOUND; /* "File not found" */
}

int
ldb_create_dir(const char *dirname) {
  (void)dirname;
  return LDB_OK;
}

int
ldb_remove_dir(const char *dirname) {
  (void)dirname;
  return LDB_OK;
}

int
ldb_get_file_size(const char *filename, uint64_t *size) {
  ldb_fstate_t *state;

  ldb_mutex_lock(&file_mutex);

  state = rb_map_get(&file_map, filename);

  if (state != NULL)
    *size = ldb_fstate_size(state);

  ldb_mutex_unlock(&file_mutex);

  return state ? LDB_OK : LDB_NOTFOUND; /* "File not found" */
}

int
ldb_rename_file(const char *from, const char *to) {
  size_t len = strlen(to);
  rb_node_t *node;

  if (len + 1 > LDB_PATH_MAX)
    return LDB_INVALID;

  ldb_mutex_lock(&file_mutex);

  node = rb_map_del(&file_map, from);

  if (node != NULL) {
    ldb_fstate_t *state = node->value.p;

    memcpy(state->path, to, len + 1);

    ldb_delete_file(to);
    rb_map_put(&file_map, state->path, state);
    rb_node_destroy(node);
  }

  ldb_mutex_unlock(&file_mutex);

  return node ? LDB_OK : LDB_NOTFOUND; /* "File not found" */
}

int
ldb_lock_file(const char *filename, ldb_filelock_t **lock) {
  size_t len = strlen(filename);

  if (len + 1 > LDB_PATH_MAX)
    return LDB_INVALID;

  ldb_mutex_lock(&file_mutex);

  if (file_set.root == NULL)
    rb_set_init(&file_set, by_string, NULL);

  if (rb_set_has(&file_set, filename)) {
    ldb_mutex_unlock(&file_mutex);
    return LDB_IOERR;
  }

  *lock = ldb_malloc(sizeof(ldb_filelock_t));

  memcpy((*lock)->path, filename, len + 1);

  rb_set_put(&file_set, (*lock)->path);

  ldb_mutex_unlock(&file_mutex);

  return LDB_OK;
}

int
ldb_unlock_file(ldb_filelock_t *lock) {
  int rc = LDB_IOERR;

  ldb_mutex_lock(&file_mutex);

  if (file_set.root && rb_set_has(&file_set, lock->path)) {
    rb_set_del(&file_set, lock->path);
    rc = LDB_OK;
  }

  ldb_free(lock);

  ldb_mutex_unlock(&file_mutex);

  return rc;
}

int
ldb_test_directory(char *result, size_t size) {
#if defined(_WIN32)
  if (size < 8)
    return 0;

  strcpy(result, "C:\\test");
#else
  if (size < 6)
    return 0;

  strcpy(result, "/test");
#endif

  return 1;
}

/*
 * Readable File
 */

struct ldb_rfile_s {
  ldb_fstate_t *state;
  size_t pos;
};

static void
ldb_rfile_init(ldb_rfile_t *file, ldb_fstate_t *state) {
  file->state = ldb_fstate_ref(state);
  file->pos = 0;
}

int
ldb_rfile_mapped(ldb_rfile_t *file) {
  (void)file;
  return 0;
}

int
ldb_rfile_read(ldb_rfile_t *file,
               ldb_slice_t *result,
               void *buf,
               size_t count) {
  int rc = ldb_fstate_pread(file->state, result, buf, count, file->pos);

  if (rc == LDB_OK)
    file->pos += result->size;

  return rc;
}

int
ldb_rfile_skip(ldb_rfile_t *file, uint64_t offset) {
  uint64_t available;

  if (file->pos > ldb_fstate_size(file->state))
    return LDB_IOERR;

  available = ldb_fstate_size(file->state) - file->pos;

  if (offset > available)
    offset = available;

  file->pos += offset;

  return LDB_OK;
}

int
ldb_rfile_pread(ldb_rfile_t *file,
                ldb_slice_t *result,
                void *buf,
                size_t count,
                uint64_t offset) {
  return ldb_fstate_pread(file->state, result, buf, count, offset);
}

/*
 * Readable File Instantiation
 */

int
ldb_seqfile_create(const char *filename, ldb_rfile_t **file) {
  ldb_fstate_t *state;

  ldb_mutex_lock(&file_mutex);

  state = rb_map_get(&file_map, filename);

  if (state != NULL) {
    *file = ldb_malloc(sizeof(ldb_rfile_t));

    ldb_rfile_init(*file, state);
  }

  ldb_mutex_unlock(&file_mutex);

  return state ? LDB_OK : LDB_NOTFOUND; /* "File not found" */
}

int
ldb_randfile_create(const char *filename, ldb_rfile_t **file, int use_mmap) {
  (void)use_mmap;
  return ldb_seqfile_create(filename, file);
}

void
ldb_rfile_destroy(ldb_rfile_t *file) {
  ldb_fstate_unref(file->state);
  ldb_free(file);
}

/*
 * Writable File
 */

struct ldb_wfile_s {
  ldb_fstate_t *state;
};

static void
ldb_wfile_init(ldb_wfile_t *file, ldb_fstate_t *state) {
  file->state = ldb_fstate_ref(state);
}

int
ldb_wfile_close(ldb_wfile_t *file) {
  (void)file;
  return LDB_OK;
}

int
ldb_wfile_append(ldb_wfile_t *file, const ldb_slice_t *data) {
  return ldb_fstate_append(file->state, data);
}

int
ldb_wfile_flush(ldb_wfile_t *file) {
  (void)file;
  return LDB_OK;
}

int
ldb_wfile_sync(ldb_wfile_t *file) {
  (void)file;
  return LDB_OK;
}

/*
 * Writable File Instantiation
 */

int
ldb_truncfile_create(const char *filename, ldb_wfile_t **file) {
  ldb_fstate_t *state;

  if (strlen(filename) + 1 > LDB_PATH_MAX)
    return LDB_INVALID;

  ldb_mutex_lock(&file_mutex);

  state = rb_map_get(&file_map, filename);

  if (state == NULL) {
    state = ldb_fstate_ref(ldb_fstate_create(filename));
    rb_map_put(&file_map, state->path, state);
  } else {
    ldb_fstate_truncate(state);
  }

  *file = ldb_malloc(sizeof(ldb_wfile_t));

  ldb_wfile_init(*file, state);

  ldb_mutex_unlock(&file_mutex);

  return LDB_OK;
}

int
ldb_appendfile_create(const char *filename, ldb_wfile_t **file) {
  ldb_fstate_t *state;

  if (strlen(filename) + 1 > LDB_PATH_MAX)
    return LDB_INVALID;

  ldb_mutex_lock(&file_mutex);

  state = rb_map_get(&file_map, filename);

  if (state == NULL) {
    state = ldb_fstate_ref(ldb_fstate_create(filename));
    rb_map_put(&file_map, state->path, state);
  }

  *file = ldb_malloc(sizeof(ldb_wfile_t));

  ldb_wfile_init(*file, state);

  ldb_mutex_unlock(&file_mutex);

  return LDB_OK;
}

void
ldb_wfile_destroy(ldb_wfile_t *file) {
  ldb_fstate_unref(file->state);
  ldb_free(file);
}

/*
 * Logging
 */

ldb_logger_t *
ldb_logger_create(FILE *stream);

int
ldb_logger_open(const char *filename, ldb_logger_t **result) {
  (void)filename;
  *result = ldb_logger_create(NULL);
  return LDB_OK;
}

/*
 * Time
 */

int64_t
ldb_now_usec(void) {
#if defined(_WIN32)
  uint64_t ticks;
  FILETIME ft;

  GetSystemTimeAsFileTime(&ft);

  ticks = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;

  return ticks / 10;
#else /* !_WIN32 */
  struct timeval tv;

  if (gettimeofday(&tv, NULL) != 0)
    abort(); /* LCOV_EXCL_LINE */

  return (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;
#endif /* !_WIN32 */
}

void
ldb_sleep_usec(int64_t usec) {
#if defined(_WIN32)
  if (usec < 0)
    usec = 0;

  Sleep(usec / 1000);
#else /* !_WIN32 */
  struct timeval tv;

  memset(&tv, 0, sizeof(tv));

  if (usec <= 0) {
    tv.tv_usec = 1;
  } else {
    tv.tv_sec = usec / 1000000;
    tv.tv_usec = usec % 1000000;
  }

  select(0, NULL, NULL, NULL, &tv);
#endif /* !_WIN32 */
}
