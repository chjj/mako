/*!
 * env_unix_impl.h - unix environment for lcdb
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
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/resource.h>

#include <dirent.h>
#include <fcntl.h>
#ifdef LDB_PTHREAD
#include <pthread.h>
#endif
#include <unistd.h>

#if !defined(FD_SETSIZE) && !defined(FD_SET)
#  include <sys/select.h>
#endif

#include "atomic.h"
#include "env.h"
#include "internal.h"
#include "port.h"
#include "rbt.h"
#include "slice.h"
#include "status.h"
#include "strutil.h"

/*
 * Compat
 */

#undef HAVE_FCNTL
#undef HAVE_MMAP
#undef HAVE_SETLK
#undef HAVE_FLOCK
#undef HAVE_FDATASYNC
#undef HAVE_PREAD

#if !defined(__wasi__) && !defined(__EMSCRIPTEN__)
#  define HAVE_FCNTL
#endif

#if !defined(__wasi__) && !defined(__EMSCRIPTEN__) && !defined(__DJGPP__)
#  include <sys/mman.h>
#  define HAVE_MMAP
#endif

#if defined(HAVE_FCNTL) && defined(F_WRLCK) && defined(F_SETLK)
#  define HAVE_SETLK
#endif

#if !defined(HAVE_SETLK) && !defined(__wasi__) && !defined(__EMSCRIPTEN__)
#  ifndef LOCK_EX
#    include <sys/file.h>
#  endif
#  ifdef LOCK_EX
#    define HAVE_FLOCK
#  endif
#endif

#if defined(__linux__) || defined(__sun) || defined(__NetBSD__)
#  define HAVE_FDATASYNC
#endif

#if !defined(__WATCOMC__) && !defined(__DJGPP__)
#  define HAVE_PREAD
#endif

/*
 * Fixes
 */

#ifndef MAP_FAILED
#  define MAP_FAILED ((void *)-1)
#endif

#ifdef __wasi__
/* lseek(3) is statement expression in wasi-libc. */
#  pragma GCC diagnostic ignored "-Wgnu-statement-expression"
#endif

/*
 * Constants
 */

#define LDB_WRITE_BUFFER 65536
#define LDB_MMAP_LIMIT (sizeof(void *) >= 8 ? 1000 : 0)
#define LDB_POSIX_ERROR(rc) ((rc) == ENOENT ? LDB_NOTFOUND : LDB_IOERR)

/*
 * Types
 */

typedef struct ldb_limiter_s {
  ldb_atomic(int) acquires_allowed;
  int max_acquires;
} ldb_limiter_t;

struct ldb_filelock_s {
  char path[LDB_PATH_MAX];
  int fd;
};

/*
 * Globals
 */

static ldb_limiter_t ldb_fd_limiter = {1638, 1638};
#ifdef HAVE_MMAP
static ldb_limiter_t ldb_mmap_limiter = {LDB_MMAP_LIMIT, LDB_MMAP_LIMIT};
#endif
static ldb_mutex_t file_mutex = LDB_MUTEX_INITIALIZER;
static rb_set_t file_set;

/*
 * Limiter
 */

static void
ldb_limiter_init(ldb_limiter_t *lim, int max_acquires) {
  assert(max_acquires >= 0);

  lim->acquires_allowed = max_acquires;
  lim->max_acquires = max_acquires;
}

static int
ldb_limiter_acquire(ldb_limiter_t *lim) {
  int old;

  old = ldb_atomic_fetch_sub(&lim->acquires_allowed, 1, ldb_order_relaxed);

  if (old > 0)
    return 1;

  old = ldb_atomic_fetch_add(&lim->acquires_allowed, 1, ldb_order_relaxed);

  assert(old < lim->max_acquires);

  (void)old;

  return 0;
}

static void
ldb_limiter_release(ldb_limiter_t *lim) {
  int old = ldb_atomic_fetch_add(&lim->acquires_allowed, 1, ldb_order_relaxed);

  assert(old < lim->max_acquires);

  (void)old;
}

/*
 * Comparator
 */

static int
by_string(rb_val_t x, rb_val_t y, void *arg) {
  (void)arg;
  return strcmp(x.p, y.p);
}

/*
 * Path Helpers
 */

static int
ldb_is_manifest(const char *filename) {
  const char *base = strrchr(filename, '/');

  if (base == NULL)
    base = filename;
  else
    base += 1;

  return ldb_starts_with(base, "MANIFEST");
}

/*
 * File Helpers
 */

static int
ldb_try_open(const char *name, int flags, uint32_t mode) {
  int fd;

#ifdef O_CLOEXEC
  if (flags & O_CREAT)
    fd = open(name, flags | O_CLOEXEC, mode);
  else
    fd = open(name, flags | O_CLOEXEC);

  if (fd >= 0 || errno != EINVAL)
    return fd;
#endif

  if (flags & O_CREAT)
    fd = open(name, flags, mode);
  else
    fd = open(name, flags);

#if defined(HAVE_FCNTL) && defined(FD_CLOEXEC)
  if (fd >= 0) {
    int r = fcntl(fd, F_GETFD);

    if (r != -1)
      fcntl(fd, F_SETFD, r | FD_CLOEXEC);
  }
#endif

  return fd;
}

static int
ldb_open(const char *name, int flags, uint32_t mode) {
  int fd;

  do {
    fd = ldb_try_open(name, flags, mode);
  } while (fd < 0 && errno == EINTR);

  return fd;
}

static int
ldb_sync_fd(int fd) {
#if defined(__APPLE__) && defined(F_FULLFSYNC)
  if (fcntl(fd, F_FULLFSYNC) == 0)
    return LDB_OK;
#endif

#ifdef HAVE_FDATASYNC
  if (fdatasync(fd) == 0)
    return LDB_OK;
#else
  if (fsync(fd) == 0)
    return LDB_OK;
#endif

  return LDB_IOERR;
}

static int
ldb_lock_or_unlock(int fd, int lock) {
#if defined(HAVE_SETLK)
  struct flock info;

  errno = 0;

  memset(&info, 0, sizeof(info));

  info.l_type = (lock ? F_WRLCK : F_UNLCK);
  info.l_whence = SEEK_SET;

  return fcntl(fd, F_SETLK, &info) == 0;
#elif defined(HAVE_FLOCK)
  return flock(fd, lock ? LOCK_EX : LOCK_UN) == 0;
#else
  (void)fd;
  (void)lock;
  return 1;
#endif
}

static int
ldb_max_open_files(void) {
#if defined(__Fuchsia__)
  return 1638;
#elif defined(RLIMIT_NOFILE)
  struct rlimit rlim;

  if (getrlimit(RLIMIT_NOFILE, &rlim) != 0)
    return 1638;

  if (rlim.rlim_cur == RLIM_INFINITY)
    return INT_MAX / 2;

  return rlim.rlim_cur / 5;
#else
  return 1638;
#endif
}

/*
 * Environment
 */

static void
env_init(void) {
  ldb_limiter_init(&ldb_fd_limiter, ldb_max_open_files());
}

static void
ldb_env_init(void) {
#if defined(LDB_PTHREAD)
  static pthread_once_t guard = PTHREAD_ONCE_INIT;
  pthread_once(&guard, env_init);
#else
  static int guard = 0;
  if (guard == 0) {
    env_init();
    guard = 1;
  }
#endif
}

/*
 * Filesystem
 */

int
ldb_path_absolute(char *buf, size_t size, const char *name) {
#if defined(__wasi__)
  size_t len = strlen(name);

  if (name[0] != '/')
    return 0;

  if (len + 1 > size)
    return 0;

  memcpy(buf, name, len + 1);

  return 1;
#else
  char cwd[LDB_PATH_MAX];

  if (name[0] == '/') {
    size_t len = strlen(name);

    if (len + 1 > size)
      return 0;

    memcpy(buf, name, len + 1);

    return 1;
  }

  if (getcwd(cwd, sizeof(cwd)) == NULL)
    return 0;

  cwd[sizeof(cwd) - 1] = '\0';

  return ldb_join(buf, size, cwd, name);
#endif
}

int
ldb_file_exists(const char *filename) {
  return access(filename, F_OK) == 0;
}

int
ldb_get_children(const char *path, char ***out) {
  struct dirent *entry;
  char **list = NULL;
  char *name = NULL;
  DIR *dir = NULL;
  size_t size = 8;
  size_t i = 0;
  size_t j, len;

  list = (char **)malloc(size * sizeof(char *));

  if (list == NULL)
    goto fail;

  dir = opendir(path);

  if (dir == NULL)
    goto fail;

  for (;;) {
    errno = 0;
    entry = readdir(dir);

    if (entry == NULL) {
      if (errno != 0)
        goto fail;
      break;
    }

    if (strcmp(entry->d_name, ".") == 0
        || strcmp(entry->d_name, "..") == 0) {
      continue;
    }

    len = strlen(entry->d_name);
    name = (char *)malloc(len + 1);

    if (name == NULL)
      goto fail;

    memcpy(name, entry->d_name, len + 1);

    if (i == size) {
      size = (size * 3) / 2;
      list = (char **)realloc(list, size * sizeof(char *));

      if (list == NULL)
        goto fail;
    }

    list[i++] = name;
    name = NULL;
  }

  closedir(dir);

  *out = list;

  return i;
fail:
  for (j = 0; j < i; j++)
    ldb_free(list[j]);

  if (list != NULL)
    ldb_free(list);

  if (name != NULL)
    ldb_free(name);

  if (dir != NULL)
    closedir(dir);

  *out = NULL;

  return -1;
}

void
ldb_free_children(char **list, int len) {
  int i;

  for (i = 0; i < len; i++)
    ldb_free(list[i]);

  ldb_free(list);
}

int
ldb_remove_file(const char *filename) {
  if (unlink(filename) != 0)
    return LDB_POSIX_ERROR(errno);

  return LDB_OK;
}

int
ldb_create_dir(const char *dirname) {
  if (mkdir(dirname, 0755) != 0)
    return LDB_POSIX_ERROR(errno);

  return LDB_OK;
}

int
ldb_remove_dir(const char *dirname) {
  if (rmdir(dirname) != 0)
    return LDB_POSIX_ERROR(errno);

  return LDB_OK;
}

int
ldb_get_file_size(const char *filename, uint64_t *size) {
  struct stat st;

  if (stat(filename, &st) != 0)
    return LDB_POSIX_ERROR(errno);

  *size = st.st_size;

  return LDB_OK;
}

int
ldb_rename_file(const char *from, const char *to) {
  if (rename(from, to) != 0)
    return LDB_POSIX_ERROR(errno);

  return LDB_OK;
}

int
ldb_lock_file(const char *filename, ldb_filelock_t **lock) {
  size_t len = strlen(filename);
  int fd;

  if (len + 1 > LDB_PATH_MAX)
    return LDB_INVALID;

  ldb_mutex_lock(&file_mutex);

  if (file_set.root == NULL)
    rb_set_init(&file_set, by_string, NULL);

  if (rb_set_has(&file_set, filename)) {
    ldb_mutex_unlock(&file_mutex);
    return LDB_IOERR;
  }

  fd = ldb_open(filename, O_RDWR | O_CREAT, 0644);

  if (fd < 0) {
    ldb_mutex_unlock(&file_mutex);
    return LDB_POSIX_ERROR(errno);
  }

  if (!ldb_lock_or_unlock(fd, 1)) {
    ldb_mutex_unlock(&file_mutex);
    close(fd);
    return LDB_IOERR;
  }

  *lock = ldb_malloc(sizeof(ldb_filelock_t));

  (*lock)->fd = fd;

  memcpy((*lock)->path, filename, len + 1);

  rb_set_put(&file_set, (*lock)->path);

  ldb_mutex_unlock(&file_mutex);

  return LDB_OK;
}

int
ldb_unlock_file(ldb_filelock_t *lock) {
  int ok = 0;

  ldb_mutex_lock(&file_mutex);

  if (file_set.root && rb_set_has(&file_set, lock->path)) {
    rb_set_del(&file_set, lock->path);
    ok = 1;
  }

  ok &= ldb_lock_or_unlock(lock->fd, 0);

  close(lock->fd);

  ldb_free(lock);

  ldb_mutex_unlock(&file_mutex);

  return ok ? LDB_OK : LDB_IOERR;
}

int
ldb_test_directory(char *result, size_t size) {
  const char *dir = getenv("TEST_TMPDIR");
  char tmp[100];
  size_t len;

  if (dir != NULL && dir[0] != '\0') {
    len = strlen(dir);
  } else {
#ifdef __wasi__
    len = sprintf(tmp, "/leveldbtest");
#else
    len = sprintf(tmp, "/tmp/leveldbtest-%d", (int)geteuid());
#endif
    dir = tmp;
  }

  if (len + 1 > size)
    return 0;

  memcpy(result, dir, len + 1);

  mkdir(result, 0755);

  return 1;
}

/*
 * Readable File
 */

struct ldb_rfile_s {
  char filename[LDB_PATH_MAX];
  int fd;
  ldb_limiter_t *limiter;
  int mapped;
  unsigned char *base;
  size_t length;
#ifndef HAVE_PREAD
  ldb_mutex_t mutex;
  int has_mutex;
#endif
};

static void
ldb_seqfile_init(ldb_rfile_t *file, const char *filename, int fd) {
  strcpy(file->filename, filename);

  file->fd = fd;
  file->limiter = NULL;
  file->mapped = 0;
  file->base = NULL;
  file->length = 0;
#ifndef HAVE_PREAD
  file->has_mutex = 0;
#endif
}

static void
ldb_randfile_init(ldb_rfile_t *file,
                  const char *filename,
                  int fd,
                  ldb_limiter_t *limiter) {
  int acquired = ldb_limiter_acquire(limiter);

  strcpy(file->filename, filename);

  file->fd = acquired ? fd : -1;
  file->limiter = acquired ? limiter : NULL;
  file->mapped = 0;
  file->base = NULL;
  file->length = 0;

#ifndef HAVE_PREAD
  ldb_mutex_init(&file->mutex);
  file->has_mutex = 1;
#endif

  if (!acquired)
    close(fd);
}

#ifdef HAVE_MMAP
static void
ldb_mapfile_init(ldb_rfile_t *file,
                 const char *filename,
                 unsigned char *base,
                 size_t length,
                 ldb_limiter_t *limiter) {
  strcpy(file->filename, filename);

  file->fd = -1;
  file->limiter = limiter;
  file->mapped = 1;
  file->base = base;
  file->length = length;
#ifndef HAVE_PREAD
  file->has_mutex = 0;
#endif
}
#endif

int
ldb_rfile_mapped(ldb_rfile_t *file) {
  return file->mapped;
}

int
ldb_rfile_read(ldb_rfile_t *file,
               ldb_slice_t *result,
               void *buf,
               size_t count) {
  ssize_t nread;

  do {
    nread = read(file->fd, buf, count);
  } while (nread < 0 && errno == EINTR);

  if (nread < 0)
    return LDB_IOERR;

  ldb_slice_set(result, buf, nread);

  return LDB_OK;
}

int
ldb_rfile_skip(ldb_rfile_t *file, uint64_t offset) {
  if (lseek(file->fd, offset, SEEK_CUR) == -1)
    return LDB_IOERR;

  return LDB_OK;
}

int
ldb_rfile_pread(ldb_rfile_t *file,
                ldb_slice_t *result,
                void *buf,
                size_t count,
                uint64_t offset) {
  int fd = file->fd;
  ssize_t nread;

  if (file->mapped) {
    if (offset + count > file->length)
      return LDB_IOERR;

    ldb_slice_set(result, file->base + offset, count);

    return LDB_OK;
  }

  if (buf == NULL)
    return LDB_INVALID;

  if (file->fd == -1) {
    fd = ldb_open(file->filename, O_RDONLY, 0);

    if (fd < 0)
      return LDB_POSIX_ERROR(errno);
  }

#ifdef HAVE_PREAD
  do {
    nread = pread(fd, buf, count, offset);
  } while (nread < 0 && errno == EINTR);
#else
  ldb_mutex_lock(&file->mutex);

  if ((uint64_t)lseek(fd, offset, SEEK_SET) == offset) {
    do {
      nread = read(fd, buf, count);
    } while (nread < 0 && errno == EINTR);
  } else {
    nread = -1;
  }

  ldb_mutex_unlock(&file->mutex);
#endif

  if (nread >= 0)
    ldb_slice_set(result, buf, nread);

  if (file->fd == -1)
    close(fd);

  return nread < 0 ? LDB_IOERR : LDB_OK;
}

static int
ldb_rfile_close(ldb_rfile_t *file) {
  int rc = LDB_OK;

  if (file->fd != -1) {
    if (close(file->fd) < 0)
      rc = LDB_IOERR;
  }

  if (file->limiter != NULL)
    ldb_limiter_release(file->limiter);

#ifdef HAVE_MMAP
  if (file->mapped)
    munmap((void *)file->base, file->length);
#endif

  file->fd = -1;
  file->limiter = NULL;
  file->mapped = 0;
  file->base = NULL;
  file->length = 0;

#ifndef HAVE_PREAD
  if (file->has_mutex) {
    ldb_mutex_destroy(&file->mutex);
    file->has_mutex = 0;
  }
#endif

  return rc;
}

/*
 * Readable File Instantiation
 */

int
ldb_seqfile_create(const char *filename, ldb_rfile_t **file) {
  int fd;

  if (strlen(filename) + 1 > LDB_PATH_MAX)
    return LDB_INVALID;

  fd = ldb_open(filename, O_RDONLY, 0);

  if (fd < 0)
    return LDB_POSIX_ERROR(errno);

  *file = ldb_malloc(sizeof(ldb_rfile_t));

  ldb_seqfile_init(*file, filename, fd);

  return LDB_OK;
}

int
ldb_randfile_create(const char *filename, ldb_rfile_t **file, int use_mmap) {
#ifdef HAVE_MMAP
  uint64_t size = 0;
  int rc = LDB_OK;
  struct stat st;
#endif
  int fd;

#ifndef HAVE_MMAP
  (void)use_mmap;
#endif

  if (strlen(filename) + 1 > LDB_PATH_MAX)
    return LDB_INVALID;

  fd = ldb_open(filename, O_RDONLY, 0);

  if (fd < 0)
    return LDB_POSIX_ERROR(errno);

#ifdef HAVE_MMAP
  if (!use_mmap || !ldb_limiter_acquire(&ldb_mmap_limiter))
#endif
  {
    *file = ldb_malloc(sizeof(ldb_rfile_t));

    ldb_env_init();
    ldb_randfile_init(*file, filename, fd, &ldb_fd_limiter);

    return LDB_OK;
  }

#ifdef HAVE_MMAP
  if (fstat(fd, &st) != 0)
    rc = LDB_POSIX_ERROR(errno);
  else
    size = st.st_size;

  if (rc == LDB_OK && size > (((size_t)-1) / 2))
    rc = LDB_IOERR;

  if (rc == LDB_OK) {
    void *base = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);

    if (base != MAP_FAILED) {
      *file = ldb_malloc(sizeof(ldb_rfile_t));

      ldb_mapfile_init(*file, filename, base, size, &ldb_mmap_limiter);
    } else {
      rc = LDB_IOERR;
    }
  }

  close(fd);

  if (rc != LDB_OK)
    ldb_limiter_release(&ldb_mmap_limiter);

  return rc;
#endif
}

void
ldb_rfile_destroy(ldb_rfile_t *file) {
  ldb_rfile_close(file);
  ldb_free(file);
}

/*
 * Writable File
 */

struct ldb_wfile_s {
  char filename[LDB_PATH_MAX];
  char dirname[LDB_PATH_MAX];
  int fd, manifest;
  unsigned char buf[LDB_WRITE_BUFFER];
  size_t pos;
};

static void
ldb_wfile_init(ldb_wfile_t *file, const char *filename, int fd) {
  strcpy(file->filename, filename);

  if (!ldb_dirname(file->dirname, LDB_PATH_MAX, filename))
    abort(); /* LCOV_EXCL_LINE */

  file->fd = fd;
  file->manifest = ldb_is_manifest(filename);
  file->pos = 0;
}

int
ldb_wfile_close(ldb_wfile_t *file) {
  int rc = ldb_wfile_flush(file);

  if (close(file->fd) < 0 && rc == LDB_OK)
    rc = LDB_IOERR;

  file->fd = -1;

  return rc;
}

static int
ldb_wfile_write(ldb_wfile_t *file, const unsigned char *data, size_t size) {
  while (size > 0) {
    ssize_t nwrite = write(file->fd, data, size);

    if (nwrite < 0) {
      if (errno == EINTR)
        continue;

      return LDB_IOERR;
    }

    data += nwrite;
    size -= nwrite;
  }

  return LDB_OK;
}

static int
ldb_wfile_sync_dir(ldb_wfile_t *file) {
  int fd, rc;

  if (!file->manifest)
    return LDB_OK;

  fd = ldb_open(file->dirname, O_RDONLY, 0);

  if (fd < 0) {
    rc = LDB_POSIX_ERROR(errno);
  } else {
    rc = ldb_sync_fd(fd);
    close(fd);
  }

  return rc;
}

int
ldb_wfile_append(ldb_wfile_t *file, const ldb_slice_t *data) {
  const unsigned char *write_data = data->data;
  size_t write_size = data->size;
  size_t copy_size;
  int rc;

  copy_size = LDB_MIN(write_size, LDB_WRITE_BUFFER - file->pos);

  memcpy(file->buf + file->pos, write_data, copy_size);

  write_data += copy_size;
  write_size -= copy_size;
  file->pos += copy_size;

  if (write_size == 0)
    return LDB_OK;

  if ((rc = ldb_wfile_flush(file)))
    return rc;

  if (write_size < LDB_WRITE_BUFFER) {
    memcpy(file->buf, write_data, write_size);
    file->pos = write_size;
    return LDB_OK;
  }

  return ldb_wfile_write(file, write_data, write_size);
}

int
ldb_wfile_flush(ldb_wfile_t *file) {
  int rc = ldb_wfile_write(file, file->buf, file->pos);
  file->pos = 0;
  return rc;
}

int
ldb_wfile_sync(ldb_wfile_t *file) {
  int rc;

  if ((rc = ldb_wfile_sync_dir(file)))
    return rc;

  if ((rc = ldb_wfile_flush(file)))
    return rc;

  return ldb_sync_fd(file->fd);
}

/*
 * Writable File Instantiation
 */

static int
ldb_wfile_create(const char *filename, int flags, ldb_wfile_t **file) {
  int fd;

  if (strlen(filename) + 1 > LDB_PATH_MAX)
    return LDB_INVALID;

  fd = ldb_open(filename, flags, 0644);

  if (fd < 0)
    return LDB_POSIX_ERROR(errno);

  *file = ldb_malloc(sizeof(ldb_wfile_t));

  ldb_wfile_init(*file, filename, fd);

  return LDB_OK;
}

int
ldb_truncfile_create(const char *filename, ldb_wfile_t **file) {
  int flags = O_TRUNC | O_WRONLY | O_CREAT;
  return ldb_wfile_create(filename, flags, file);
}

int
ldb_appendfile_create(const char *filename, ldb_wfile_t **file) {
  int flags = O_APPEND | O_WRONLY | O_CREAT;
  return ldb_wfile_create(filename, flags, file);
}

void
ldb_wfile_destroy(ldb_wfile_t *file) {
  if (file->fd >= 0)
    close(file->fd);

  ldb_free(file);
}

/*
 * Logging
 */

ldb_logger_t *
ldb_logger_create(FILE *stream);

int
ldb_logger_open(const char *filename, ldb_logger_t **result) {
  int fd = ldb_open(filename, O_APPEND | O_WRONLY | O_CREAT, 0644);
  FILE *stream;

  if (fd < 0)
    return LDB_POSIX_ERROR(errno);

  stream = fdopen(fd, "w");

  if (stream == NULL) {
    int code = errno;
    close(fd);
    return LDB_POSIX_ERROR(code);
  }

  *result = ldb_logger_create(stream);

  return LDB_OK;
}

/*
 * Time
 */

int64_t
ldb_now_usec(void) {
  struct timeval tv;

  if (gettimeofday(&tv, NULL) != 0)
    abort(); /* LCOV_EXCL_LINE */

  return (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;
}

void
ldb_sleep_usec(int64_t usec) {
  struct timeval tv;

  memset(&tv, 0, sizeof(tv));

  if (usec <= 0) {
    tv.tv_usec = 1;
  } else {
    tv.tv_sec = usec / 1000000;
    tv.tv_usec = usec % 1000000;
  }

  select(0, NULL, NULL, NULL, &tv);
}
