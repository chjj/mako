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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>

#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>

#if !defined(__Fuchsia__) && !defined(__wasi__) && !defined(__EMSCRIPTEN__)
#  include <sys/resource.h>
#endif

#if !defined(FD_SETSIZE) && !defined(FD_SET)
#  include <sys/select.h>
#endif

#ifdef LDB_PTHREAD
#  include <pthread.h>
#endif

#include "atomic.h"
#include "buffer.h"
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

#if !defined(__DJGPP__) && !defined(__wasi__) && !defined(__EMSCRIPTEN__)
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

#ifdef LDB_HAVE_FDATASYNC
#  define HAVE_FDATASYNC
#endif

#ifdef LDB_HAVE_PREAD
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
#define LDB_OFFSET_MAX (sizeof(off_t) >= 8 ? INT64_MAX : INT32_MAX)

/*
 * Types
 */

typedef struct ldb_limiter_s {
  ldb_atomic(int) acquires_allowed;
  int max_acquires;
} ldb_limiter_t;

typedef struct ldb_fileid_s {
  uint64_t dev;
  uint64_t ino;
} ldb_fileid_t;

struct ldb_filelock_s {
  ldb_fileid_t id;
  int fd;
};

/*
 * Globals
 */

static ldb_limiter_t ldb_fd_limiter = {50, 50};
#ifdef HAVE_MMAP
static ldb_limiter_t ldb_mmap_limiter = {LDB_MMAP_LIMIT, LDB_MMAP_LIMIT};
#endif
static ldb_mutex_t file_mutex = LDB_MUTEX_INITIALIZER;

/*
 * Limiter
 */

static void
ldb_limiter_init(ldb_limiter_t *lim, int max_acquires) {
  assert(max_acquires >= 0);

  ldb_atomic_init(&lim->acquires_allowed, max_acquires);

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
 * File Set
 */

static int
by_fileid(rb_val_t x, rb_val_t y, void *arg) {
  const ldb_fileid_t *xp = x.ptr;
  const ldb_fileid_t *yp = y.ptr;
  int r = LDB_CMP(xp->dev, yp->dev);

  (void)arg;

  if (r != 0)
    return r;

  return LDB_CMP(xp->ino, yp->ino);
}

static rb_set_t file_set = RB_SET_INIT(by_fileid);

/*
 * Errors
 */

int
ldb_system_error(void) {
  int code = errno;

  if (code == 0)
    return LDB_IOERR;

  return code;
}

/* Thread-safety of strerror(3):
 *
 *   msvcrt - yes
 *   borland - yes
 *   watcom - yes
 *   glibc - yes
 *   musl - yes
 *   bionic - yes
 *   dietlibc - yes
 *   uclibc - no
 *   newlib - yes
 *   apple - if libc is built w/o NLS
 *   freebsd - no
 *   openbsd - no
 *   netbsd - yes
 *   dragonfly - no
 *   solaris - yes
 *   illumos - yes
 *   cygwin - yes
 *   hpux - ??
 *   aix - ??
 *   qnx - yes
 *   haiku - if known errno
 *   minix - yes
 *   plan9 - yes
 *   tru64 - ??
 *   irix - ??
 *   sco - ??
 *   redox - yes
 *   fuchsia - yes
 *   wasi - yes
 *   emscripten - yes
 *   cosmopolitan - no
 *
 * Luckily, the platforms which are not
 * thread-safe also support sys_errlist.
 */
#undef USE_SYS_ERRLIST

#if (defined(__APPLE__)     \
  || defined(__FreeBSD__)   \
  || defined(__OpenBSD__)   \
  || defined(__DragonFly__) \
  || defined(__hpux)        \
  || defined(__sgi)         \
  || defined(_AIX))
#  ifdef __APPLE__
/* Apple has some stupid FTMs. */
extern const char *const sys_errlist[];
extern const int sys_nerr;
#  endif
/* AIX and IRIX also have some stupid FTMs. */
/* HP-UX 9.07 only declares these for C++. */
#  if defined(_AIX) || defined(__hpux) || defined(__sgi)
extern char *sys_errlist[];
extern int sys_nerr;
#  endif
#  define USE_SYS_ERRLIST
#endif

const char *
ldb_error_string(int code) {
#ifdef USE_SYS_ERRLIST
  if (code < 0 || code >= sys_nerr)
    return "Unknown error";

  return sys_errlist[code];
#else
  const char *msg = strerror(code);

  if (msg == NULL)
    return "Unknown error";

  return msg;
#endif
}

/*
 * Helpers
 */

static char *
ldb_strdup(const char *xp) {
  size_t xn = strlen(xp);
  return memcpy(ldb_malloc(xn + 1), xp, xn + 1);
}

static int
ldb_is_manifest(const char *filename) {
  const char *base = strrchr(filename, '/');

  if (base == NULL)
    base = filename;
  else
    base += 1;

  return ldb_starts_with(base, "MANIFEST");
}

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

static int64_t
ldb_read(int fd, void *dst, size_t len) {
  unsigned char *buf = dst;
  int64_t cnt = 0;

  while (len > 0) {
    size_t max = LDB_MIN(len, 1 << 30);
    int nread;

    do {
      nread = read(fd, buf, max);
    } while (nread < 0 && errno == EINTR);

    if (nread < 0)
      return -1;

    if (nread == 0)
      break;

    buf += nread;
    len -= nread;
    cnt += nread;
  }

  return cnt;
}

#ifdef HAVE_PREAD
static int64_t
ldb_pread(int fd, void *dst, size_t len, uint64_t off) {
  unsigned char *buf = dst;
  int64_t cnt = 0;

  while (len > 0) {
    size_t max = LDB_MIN(len, 1 << 30);
    int nread;

    do {
      nread = pread(fd, buf, max, off);
    } while (nread < 0 && errno == EINTR);

    if (nread < 0)
      return -1;

    if (nread == 0)
      break;

    buf += nread;
    len -= nread;
    off += nread;
    cnt += nread;
  }

  return cnt;
}
#endif

static int64_t
ldb_write(int fd, const void *src, size_t len) {
  const unsigned char *buf = src;
  int64_t cnt = 0;

  while (len > 0) {
    size_t max = LDB_MIN(len, 1 << 30);
    int nwrite;

    do {
      nwrite = write(fd, buf, max);
    } while (nwrite < 0 && errno == EINTR);

    if (nwrite < 0)
      return -1;

    buf += nwrite;
    len -= nwrite;
    cnt += nwrite;
  }

  return cnt;
}

static int
ldb_fsync(int fd) {
  int rc;

#if defined(__APPLE__) && defined(F_FULLFSYNC)
  if (fcntl(fd, F_FULLFSYNC) == 0)
    return 0;
#endif

  do {
#ifdef HAVE_FDATASYNC
    rc = fdatasync(fd);

    if (rc != 0 && errno == ENOSYS)
      rc = fsync(fd);
#else
    rc = fsync(fd);
#endif
  } while (rc != 0 && errno == EINTR);

  return rc;
}

static int
ldb_flock(int fd, int lock) {
#if defined(HAVE_SETLK)
  struct flock info;

  memset(&info, 0, sizeof(info));

  info.l_type = lock ? F_WRLCK : F_UNLCK;
  info.l_whence = SEEK_SET;

  return fcntl(fd, F_SETLK, &info);
#elif defined(HAVE_FLOCK)
  return flock(fd, lock ? (LOCK_EX | LOCK_NB) : LOCK_UN);
#else
  (void)fd;
  (void)lock;
  return 0;
#endif
}

static int
ldb_max_open_files(void) {
#if defined(__Fuchsia__)
  return sysconf(_SC_OPEN_MAX); /* FDIO_MAX_FD */
#elif defined(__wasi__) || defined(__EMSCRIPTEN__)
  return 8192; /* Linux default. */
#elif defined(RLIMIT_NOFILE)
  struct rlimit rlim;

  if (getrlimit(RLIMIT_NOFILE, &rlim) != 0)
    return -1;

#ifdef RLIM_INFINITY
  if (rlim.rlim_cur == RLIM_INFINITY)
    return INT_MAX;
#endif

  if (rlim.rlim_cur < 1)
    return -1;

  if (rlim.rlim_cur > INT_MAX - 1)
    return INT_MAX;

  return rlim.rlim_cur;
#else
  return -1;
#endif
}

/*
 * Environment
 */

static void
env_init(void) {
  int max_open = ldb_max_open_files();

  if (max_open > 0)
    ldb_limiter_init(&ldb_fd_limiter, max_open / 5);
}

static void
ldb_env_init(void) {
#ifdef LDB_PTHREAD
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
#ifdef __wasi__
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
  void *ptr;

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

    if (strcmp(entry->d_name, ".") == 0 ||
        strcmp(entry->d_name, "..") == 0) {
      continue;
    }

    len = strlen(entry->d_name);
    name = (char *)malloc(len + 1);

    if (name == NULL)
      goto fail;

    memcpy(name, entry->d_name, len + 1);

    if (i == size) {
      size = (size * 3) / 2;
      ptr = realloc(list, size * sizeof(char *));

      if (ptr == NULL)
        goto fail;

      list = (char **)ptr;
    }

    list[i++] = name;
    name = NULL;
  }

  closedir(dir);

  *out = list;

  return i;
fail:
  for (j = 0; j < i; j++)
    free(list[j]);

  if (list != NULL)
    free(list);

  if (name != NULL)
    free(name);

  if (dir != NULL)
    closedir(dir);

  *out = NULL;

  return -1;
}

void
ldb_free_children(char **list, int len) {
  int i;

  for (i = 0; i < len; i++)
    free(list[i]);

  if (list != NULL)
    free(list);
}

int
ldb_remove_file(const char *filename) {
  if (unlink(filename) != 0)
    return ldb_system_error();

  return LDB_OK;
}

int
ldb_create_dir(const char *dirname) {
  if (mkdir(dirname, 0755) != 0)
    return ldb_system_error();

  return LDB_OK;
}

int
ldb_remove_dir(const char *dirname) {
  if (rmdir(dirname) != 0)
    return ldb_system_error();

  return LDB_OK;
}

int
ldb_sync_dir(const char *dirname) {
  int fd = ldb_open(dirname, O_RDONLY, 0);
  int rc = LDB_OK;

  if (fd < 0) {
    rc = ldb_system_error();
  } else {
#ifdef __wasi__
    if (fsync(fd) != 0)
      rc = ldb_system_error();
#else
    if (ldb_fsync(fd) != 0)
      rc = ldb_system_error();
#endif

    if (rc == EBADF || rc == EINVAL)
      rc = LDB_OK;

    close(fd);
  }

  return rc;
}

int
ldb_file_size(const char *filename, uint64_t *size) {
  struct stat st;

  if (stat(filename, &st) != 0)
    return ldb_system_error();

  *size = st.st_size;

  return LDB_OK;
}

int
ldb_rename_file(const char *from, const char *to) {
  if (rename(from, to) != 0)
    return ldb_system_error();

  return LDB_OK;
}

int
ldb_copy_file(const char *from, const char *to) {
  const size_t buflen = (1 << 20);
  unsigned char *buf, *ptr;
  int rc = LDB_IOERR;
  int len, nwrite;
  struct stat st;
  int nread = -1;
  int rfd = -1;
  int wfd = -1;

  rfd = ldb_open(from, O_RDONLY, 0);

  if (rfd < 0)
    return ldb_system_error();

  errno = EPERM;

  if (fstat(rfd, &st) != 0 || !S_ISREG(st.st_mode)) {
    rc = ldb_system_error();
    close(rfd);
    return rc;
  }

  wfd = ldb_open(to, O_WRONLY | O_CREAT | O_EXCL, 0644);

  if (wfd < 0) {
    rc = ldb_system_error();
    close(rfd);
    return rc;
  }

  buf = malloc(buflen);

  if (buf == NULL)
    goto fail;

  for (;;) {
    do {
      nread = read(rfd, buf, buflen);
    } while (nread < 0 && errno == EINTR);

    if (nread < 0)
      goto fail;

    if (nread == 0)
      break;

    ptr = buf;
    len = nread;

    while (len > 0) {
      do {
        nwrite = write(wfd, ptr, len);
      } while (nwrite < 0 && errno == EINTR);

      if (nwrite < 0)
        goto fail;

      ptr += nwrite;
      len -= nwrite;
    }
  }

  if (ldb_fsync(wfd) != 0)
    goto fail;

  rc = LDB_OK;
fail:
  if (rc != LDB_OK)
    rc = ldb_system_error();

  if (close(wfd) != 0 && rc == LDB_OK)
    rc = ldb_system_error();

  close(rfd);

  if (buf != NULL)
    free(buf);

  if (rc != LDB_OK)
    unlink(to);

  return rc;
}

static int
ldb_should_copy(int code) {
  /* Cross-device link (V7). */
  if (code == EXDEV)
    return 1;

  /* Too many links (V7). */
  if (code == EMLINK)
    return 1;

#ifdef ENOSYS
  /* Function not supported. */
  if (code == ENOSYS)
    return 1;
#endif

#if defined(__linux__) || defined(__CYGWIN__)
  /* No hard link support (Linux, Cygwin). */
  if (code == EPERM)
    return 1;
#endif

#ifdef EOPNOTSUPP
  /* No hard link support (*BSD). */
  if (code == EOPNOTSUPP)
    return 1;
#endif

#ifdef ENOTSUP
  /* Possibly returned by IBM i. */
  if (code == ENOTSUP)
    return 1;
#endif

  return 0;
}

int
ldb_link_file(const char *from, const char *to) {
  if (link(from, to) != 0) {
    if (ldb_should_copy(errno))
      return ldb_copy_file(from, to);

    return ldb_system_error();
  }

  return LDB_OK;
}

int
ldb_lock_file(const char *filename, ldb_filelock_t **lock) {
  ldb_fileid_t id;
  struct stat st;
  int fd, rc;

  ldb_mutex_lock(&file_mutex);

  fd = ldb_open(filename, O_RDWR | O_CREAT, 0644);

  if (fd < 0 || fstat(fd, &st) != 0)
    goto fail;

  id.dev = st.st_dev;
  id.ino = st.st_ino;

  if (rb_set_has(&file_set, &id)) {
    errno = ENOLCK;
    goto fail;
  }

  if (ldb_flock(fd, 1) != 0)
    goto fail;

  *lock = ldb_malloc(sizeof(ldb_filelock_t));

  (*lock)->id = id;
  (*lock)->fd = fd;

  rb_set_put(&file_set, &(*lock)->id);

  ldb_mutex_unlock(&file_mutex);

  return LDB_OK;
fail:
  rc = ldb_system_error();

  if (fd >= 0)
    close(fd);

  ldb_mutex_unlock(&file_mutex);

  return rc;
}

int
ldb_unlock_file(ldb_filelock_t *lock) {
  int rc = LDB_OK;

  ldb_mutex_lock(&file_mutex);

  rb_set_del(&file_set, &lock->id);

  if (ldb_flock(lock->fd, 0) != 0)
    rc = ldb_system_error();

  close(lock->fd);

  ldb_free(lock);

  ldb_mutex_unlock(&file_mutex);

  return rc;
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
    if (access("/tmp", R_OK | W_OK) == 0)
      len = sprintf(tmp, "/tmp/leveldbtest");
    else
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
 * ReadableFile (backend)
 */

struct ldb_rfile_s {
  char *filename;
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
ldb_seqfile_init(ldb_rfile_t *file, int fd) {
  file->filename = NULL;
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

  file->filename = acquired ? NULL : ldb_strdup(filename);
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
                 unsigned char *base,
                 size_t length,
                 ldb_limiter_t *limiter) {
  file->filename = NULL;
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
  int64_t nread = ldb_read(file->fd, buf, count);

  if (nread < 0)
    return ldb_system_error();

  ldb_slice_set(result, buf, nread);

  return LDB_OK;
}

int
ldb_rfile_skip(ldb_rfile_t *file, uint64_t offset) {
  if (offset > LDB_OFFSET_MAX)
    return EINVAL;

  if (lseek(file->fd, offset, SEEK_CUR) < 0)
    return ldb_system_error();

  return LDB_OK;
}

static LDB_INLINE int
ldb_rfile_pread0(ldb_rfile_t *file,
                 ldb_slice_t *result,
                 void *buf,
                 size_t count,
                 uint64_t offset) {
  int64_t nread = -1;
  int fd = file->fd;
  int rc = LDB_OK;

  if (file->mapped) {
    if (offset + count < count)
      return EINVAL;

    if (offset + count > file->length)
      return EINVAL;

    ldb_slice_set(result, file->base + offset, count);

    return LDB_OK;
  }

  if (offset > LDB_OFFSET_MAX)
    return EINVAL;

  if (file->fd == -1) {
    fd = ldb_open(file->filename, O_RDONLY, 0);

    if (fd < 0)
      return ldb_system_error();
  }

#ifdef HAVE_PREAD
  nread = ldb_pread(fd, buf, count, offset);
#else
  ldb_mutex_lock(&file->mutex);

  if (lseek(fd, offset, SEEK_SET) >= 0)
    nread = ldb_read(fd, buf, count);

  ldb_mutex_unlock(&file->mutex);
#endif

  if (nread < 0) {
    rc = ldb_system_error();
    nread = 0;
  }

  if (file->fd == -1)
    close(fd);

  ldb_slice_set(result, buf, nread);

  return rc;
}

static int
ldb_rfile_close(ldb_rfile_t *file) {
  int rc = LDB_OK;

  if (file->filename != NULL)
    ldb_free(file->filename);

  if (file->fd != -1) {
    if (close(file->fd) != 0)
      rc = ldb_system_error();
  }

#ifdef HAVE_MMAP
  if (file->mapped)
    munmap((void *)file->base, file->length);
#endif

  if (file->limiter != NULL)
    ldb_limiter_release(file->limiter);

  file->filename = NULL;
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

void
ldb_rfile_destroy(ldb_rfile_t *file) {
  ldb_rfile_close(file);
  ldb_free(file);
}

/*
 * SequentialFile
 */

int
ldb_seqfile_create(const char *filename, ldb_rfile_t **file) {
  int fd = ldb_open(filename, O_RDONLY, 0);

  if (fd < 0)
    return ldb_system_error();

  *file = ldb_malloc(sizeof(ldb_rfile_t));

  ldb_seqfile_init(*file, fd);

  return LDB_OK;
}

/*
 * RandomAccessFile
 */

int
ldb_randfile_create(const char *filename, ldb_rfile_t **file, int use_mmap) {
#ifdef HAVE_MMAP
  void *base = NULL;
  size_t size = 0;
  int rc = LDB_OK;
  struct stat st;
#endif
  int fd;

#ifndef HAVE_MMAP
  (void)use_mmap;
#endif

  fd = ldb_open(filename, O_RDONLY, 0);

  if (fd < 0)
    return ldb_system_error();

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
    rc = ldb_system_error();

  if (rc == LDB_OK) {
    size = st.st_size;
    base = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);

    if (base == MAP_FAILED)
      rc = ldb_system_error();
  }

  if (rc == LDB_OK) {
    *file = ldb_malloc(sizeof(ldb_rfile_t));

    ldb_mapfile_init(*file, base, size, &ldb_mmap_limiter);
  }

  close(fd);

  if (rc != LDB_OK)
    ldb_limiter_release(&ldb_mmap_limiter);

  return rc;
#endif
}

/*
 * WritableFile (backend)
 */

struct ldb_wfile_s {
  char *dirname;
  int fd, manifest;
  unsigned char buf[LDB_WRITE_BUFFER];
  size_t pos;
};

static void
ldb_wfile_init(ldb_wfile_t *file, const char *filename, int fd) {
  file->dirname = NULL;
  file->fd = fd;
  file->manifest = ldb_is_manifest(filename);
  file->pos = 0;

  if (file->manifest) {
    size_t size = strlen(filename) + 2;

    file->dirname = ldb_malloc(size);

    if (!ldb_dirname(file->dirname, size, filename))
      abort(); /* LCOV_EXCL_LINE */
  }
}

static int
ldb_wfile_create(const char *filename, int flags, ldb_wfile_t **file) {
  int fd = ldb_open(filename, flags, 0644);

  if (fd < 0)
    return ldb_system_error();

  *file = ldb_malloc(sizeof(ldb_wfile_t));

  ldb_wfile_init(*file, filename, fd);

  return LDB_OK;
}

static int
ldb_wfile_write(ldb_wfile_t *file, const unsigned char *data, size_t size) {
  if (ldb_write(file->fd, data, size) < 0)
    return ldb_system_error();

  return LDB_OK;
}

static int
ldb_wfile_sync_dir(ldb_wfile_t *file) {
  if (!file->manifest)
    return LDB_OK;

  return ldb_sync_dir(file->dirname);
}

static LDB_INLINE int
ldb_wfile_append0(ldb_wfile_t *file, const ldb_slice_t *data) {
  const unsigned char *write_data = data->data;
  size_t write_size = data->size;
  size_t copy_size;
  int rc;

  copy_size = LDB_MIN(write_size, LDB_WRITE_BUFFER - file->pos);

  if (copy_size > 0) {
    memcpy(file->buf + file->pos, write_data, copy_size);

    write_data += copy_size;
    write_size -= copy_size;
    file->pos += copy_size;
  }

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

static LDB_INLINE int
ldb_wfile_sync0(ldb_wfile_t *file) {
  int rc;

  if ((rc = ldb_wfile_sync_dir(file)))
    return rc;

  if ((rc = ldb_wfile_flush(file)))
    return rc;

  if (ldb_fsync(file->fd) != 0)
    return ldb_system_error();

  return LDB_OK;
}

int
ldb_wfile_close(ldb_wfile_t *file) {
  int rc = ldb_wfile_flush(file);

  if (close(file->fd) != 0 && rc == LDB_OK)
    rc = ldb_system_error();

  file->fd = -1;

  return rc;
}

void
ldb_wfile_destroy(ldb_wfile_t *file) {
  if (file->dirname != NULL)
    ldb_free(file->dirname);

  if (file->fd >= 0)
    close(file->fd);

  ldb_free(file);
}

/*
 * WritableFile
 */

static LDB_INLINE int
ldb_truncfile_create0(const char *filename, ldb_wfile_t **file) {
  int flags = O_TRUNC | O_WRONLY | O_CREAT;
  return ldb_wfile_create(filename, flags, file);
}

/*
 * AppendableFile
 */

static LDB_INLINE int
ldb_appendfile_create0(const char *filename, ldb_wfile_t **file) {
  int flags = O_APPEND | O_WRONLY | O_CREAT;
  return ldb_wfile_create(filename, flags, file);
}

/*
 * Logging
 */

int
ldb_logger_open(const char *filename, ldb_logger_t **result) {
  int fd = ldb_open(filename, O_APPEND | O_WRONLY | O_CREAT, 0644);
  FILE *stream;

  if (fd < 0)
    return ldb_system_error();

  stream = fdopen(fd, "w");

  if (stream == NULL) {
    int rc = ldb_system_error();
    close(fd);
    return rc;
  }

  *result = ldb_logger_fopen(stream);

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
