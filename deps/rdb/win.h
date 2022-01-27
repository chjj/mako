/*!
 * win.h - windows compat for rdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifndef RDB_WIN_H
#define RDB_WIN_H

#include <windows.h>
#include <io.h>

/*
 * Options
 */

#undef RDB_MMAP
#undef RDB_PTHREAD
#undef RDB_TLS

#define RDB_PTHREAD

#ifndef __MINGW32__
#  define RDB_TLS __declspec(thread)
#endif

/*
 * Aliases
 */

#define timeval rdb__timeval /* winsock.h */
#define open rdb__open /* io.h */
#define close rdb__close /* io.h */
#define rename rdb__rename /* stdio.h */
#define unlink rdb__unlink /* stdio.h */
#define write rdb__write /* io.h */

/*
 * Compiler
 */

#ifdef __GNUC__
#  define RDB_UNUSED __attribute__((__unused__))
#  pragma GCC diagnostic ignored "-Wimplicit-fallthrough"
#else
#  define RDB_UNUSED
#endif

/*
 * Constants
 */

#define O_RDONLY     (1 <<  0)
#define O_WRONLY     (1 <<  1)
#define O_RDWR       (1 <<  2)
#define O_APPEND     (1 <<  3)
#define O_CREAT      (1 <<  4)
#define O_DSYNC      (1 <<  5)
#define O_EXCL       (1 <<  6)
#define O_SYNC       (1 <<  7)
#define O_TRUNC      (1 <<  8)
#define O_EXLOCK     (1 <<  9)
#define O_SEQUENTIAL (1 << 10)
#define O_RANDOM     (1 << 11)

#define F_SETLK 0
#define F_RDLCK 0
#define F_WRLCK 1
#define F_UNLCK 2

#ifndef EINTR
#define EINTR 4
#endif

#ifndef EINVAL
#define EINVAL 22
#endif

#define PTHREAD_MUTEX_INITIALIZER {0, NULL, {0}}

/*
 * Types
 */

struct stat {
  int64_t st_size;
};

struct flock {
  int l_type;
};

struct timeval {
  long tv_sec;
  long tv_usec;
};

typedef struct rdb_args_s {
  void *(*start)(void *);
  void *arg;
} rdb_args_t;

typedef struct pthread_mutex_s {
  int initialized;
  HANDLE event;
  CRITICAL_SECTION lock;
} pthread_mutex_t;

typedef struct pthread_cond_s {
  int waiters;
  CRITICAL_SECTION lock;
  HANDLE signal;
  HANDLE broadcast;
} pthread_cond_t;

typedef HANDLE pthread_t;

typedef int pthread_mutexattr_t;
typedef int pthread_condattr_t;
typedef int pthread_attr_t;

/*
 * I/O
 */

static int
open(const char *name, int flags, ...) {
  DWORD access;
  DWORD share;
  DWORD disposition;
  DWORD attributes;
  HANDLE handle;
  va_list ap;
  int fd;

  switch (flags & (O_RDONLY | O_WRONLY | O_RDWR)) {
    case O_RDONLY:
      access = FILE_GENERIC_READ;
      break;
    case O_WRONLY:
      access = FILE_GENERIC_WRITE;
      break;
    case O_RDWR:
      access = FILE_GENERIC_READ | FILE_GENERIC_WRITE;
      break;
    default:
      return -1;
  }

  if (flags & O_APPEND) {
    access &= ~FILE_WRITE_DATA;
    access |= FILE_APPEND_DATA;
  }

  if (!(flags & O_EXLOCK))
    share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
  else
    share = 0;

  switch (flags & (O_CREAT | O_EXCL | O_TRUNC)) {
    case 0:
    case O_EXCL:
      disposition = OPEN_EXISTING;
      break;
    case O_CREAT:
      disposition = OPEN_ALWAYS;
      break;
    case O_CREAT | O_EXCL:
    case O_CREAT | O_TRUNC | O_EXCL:
      disposition = CREATE_NEW;
      break;
    case O_TRUNC:
    case O_TRUNC | O_EXCL:
      disposition = TRUNCATE_EXISTING;
      break;
    case O_CREAT | O_TRUNC:
      disposition = CREATE_ALWAYS;
      break;
    default:
      return -1;
  }

  attributes = FILE_ATTRIBUTE_NORMAL;

  va_start(ap, flags);

  if (flags & O_CREAT) {
    unsigned int mode = va_arg(ap, unsigned int);

    if (!(mode & 00200))
      attributes |= FILE_ATTRIBUTE_READONLY;
  }

  va_end(ap);

  switch (flags & (O_SEQUENTIAL | O_RANDOM)) {
    case 0:
      break;
    case O_SEQUENTIAL:
      attributes |= FILE_FLAG_SEQUENTIAL_SCAN;
      break;
    case O_RANDOM:
      attributes |= FILE_FLAG_RANDOM_ACCESS;
      break;
    default:
      return -1;
  }

  switch (flags & (O_DSYNC | O_SYNC)) {
    case 0:
      break;
    case O_DSYNC:
    case O_SYNC:
      attributes |= FILE_FLAG_WRITE_THROUGH;
      break;
    default:
      return -1;
  }

  attributes |= FILE_FLAG_BACKUP_SEMANTICS;

  handle = CreateFileA(name, access, share, NULL,
                       disposition, attributes, NULL);

  if (handle == INVALID_HANDLE_VALUE)
    return -1;

  fd = _open_osfhandle((intptr_t)handle, 0);

  if (fd < 0) {
    CloseHandle(handle);
    return -1;
  }

  return fd;
}

static int
close(int fd) {
  return _close(fd);
}

static int
fstat(int fd, struct stat *st) {
  HANDLE handle = (HANDLE)_get_osfhandle(fd);
  LARGE_INTEGER size;

  if (handle == INVALID_HANDLE_VALUE)
    return -1;

  if (!GetFileSizeEx(handle, &size))
    return -1;

  st->st_size = size.QuadPart;

  return 0;
}

static int
rename(const char *oldpath, const char *newpath) {
  if (!MoveFileExA(oldpath, newpath, MOVEFILE_REPLACE_EXISTING))
    return -1;
  return 0;
}

static int
unlink(const char *name) {
  if (!DeleteFileA(name))
    return -1;
  return 0;
}

static int64_t
write(int fd, const void *src, size_t len) {
  HANDLE handle = (HANDLE)_get_osfhandle(fd);
  DWORD nwrite;

  if (handle == INVALID_HANDLE_VALUE)
    return -1;

  if (!WriteFile(handle, src, len, &nwrite, NULL))
    return -1;

  return nwrite;
}

static int64_t
pread(int fd, void *dst, size_t len, int64_t pos) {
  HANDLE handle = (HANDLE)_get_osfhandle(fd);
  unsigned char *raw = (unsigned char *)dst;
  LARGE_INTEGER zero, old, pos_;
  int restore = 0;
  OVERLAPPED ol;
  DWORD nread;

  if (handle == INVALID_HANDLE_VALUE)
    return -1;

  zero.QuadPart = 0;

  memset(&ol, 0, sizeof(ol));

  if (SetFilePointerEx(handle, zero, &old, FILE_CURRENT))
    restore = 1;

  while (len > 0) {
    pos_.QuadPart = pos;

    ol.Offset = pos_.LowPart;
    ol.OffsetHigh = pos_.HighPart;

    if (!ReadFile(handle, raw, len, &nread, &ol))
      return -1;

    if ((size_t)nread > len)
      abort();

    raw += nread;
    len -= nread;
    pos += nread;
  }

  if (restore)
    SetFilePointerEx(handle, old, NULL, FILE_BEGIN);

  return raw - (unsigned char *)dst;
}

static int
ftruncate(int fd, int64_t size) {
  HANDLE handle = (HANDLE)_get_osfhandle(fd);
  LARGE_INTEGER pos;

  if (handle == INVALID_HANDLE_VALUE)
    return -1;

  pos.QuadPart = size;

  if (!SetFilePointerEx(handle, pos, NULL, FILE_BEGIN))
    return -1;

  if (!SetEndOfFile(handle))
    return -1;

  return 0;
}

static int
fsync(int fd) {
  HANDLE handle = (HANDLE)_get_osfhandle(fd);

  if (handle == INVALID_HANDLE_VALUE)
    return -1;

  if (!FlushFileBuffers(handle))
    return -1;

  return 0;
}

static int
fcntl(int fd, int cmd, struct flock *fl) {
  HANDLE handle = (HANDLE)_get_osfhandle(fd);
  DWORD flags = LOCKFILE_FAIL_IMMEDIATELY;
  OVERLAPPED ol;

  if (handle == INVALID_HANDLE_VALUE)
    return -1;

  if (cmd != F_SETLK)
    return -1;

  memset(&ol, 0, sizeof(ol));

  switch (fl->l_type) {
    case F_WRLCK:
      flags |= LOCKFILE_EXCLUSIVE_LOCK;
    case F_RDLCK:
      return LockFileEx(handle, flags, 0, MAXDWORD, MAXDWORD, &ol) ? 0 : -1;
    case F_UNLCK:
      return UnlockFileEx(handle, 0, MAXDWORD, MAXDWORD, &ol) ? 0 : -1;
  }

  return -1;
}

static int
gettimeofday(struct timeval *tp, void *tzp) {
  static const uint64_t epoch = UINT64_C(116444736000000000);
  ULARGE_INTEGER ul;
  FILETIME ft;

  (void)tzp;

  GetSystemTimeAsFileTime(&ft);

  ul.LowPart = ft.dwLowDateTime;
  ul.HighPart = ft.dwHighDateTime;

  tp->tv_sec = (ul.QuadPart - epoch) / 10000000;
  tp->tv_usec = ((ul.QuadPart - epoch) % 10000000) / 10;

  return 0;
}

/*
 * Pthread
 */

static void
pthread_mutex_tryinit(pthread_mutex_t *mutex) {
  HANDLE created, existing;

  if (mutex->initialized == 0) {
    created = CreateEventA(NULL, 1, 0, NULL);

    if (created == NULL)
      abort(); /* LCOV_EXCL_LINE */

    existing = InterlockedCompareExchangePointer(&mutex->event, created, NULL);

    if (existing == NULL) {
      InitializeCriticalSection(&mutex->lock);

      if (!SetEvent(created))
        abort(); /* LCOV_EXCL_LINE */

      mutex->initialized = 1;
    } else {
      CloseHandle(created);

      if (WaitForSingleObject(existing, INFINITE) != WAIT_OBJECT_0)
        abort(); /* LCOV_EXCL_LINE */
    }
  }
}

RDB_UNUSED static int
pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr) {
  (void)attr;
  mutex->initialized = 1;
  mutex->event = NULL;
  InitializeCriticalSection(&mutex->lock);
  return 0;
}

RDB_UNUSED static int
pthread_mutex_destroy(pthread_mutex_t *mutex) {
  DeleteCriticalSection(&mutex->lock);
  return 0;
}

RDB_UNUSED static int
pthread_mutex_lock(pthread_mutex_t *mutex) {
  pthread_mutex_tryinit(mutex);
  EnterCriticalSection(&mutex->lock);
  return 0;
}

RDB_UNUSED static int
pthread_mutex_unlock(pthread_mutex_t *mutex) {
  LeaveCriticalSection(&mutex->lock);
  return 0;
}

RDB_UNUSED static int
pthread_cond_init(pthread_cond_t *cond, const pthread_condattr_t *attr) {
  (void)attr;

  cond->waiters = 0;

  InitializeCriticalSection(&cond->lock);

  cond->signal = CreateEventA(NULL, FALSE, FALSE, NULL);

  if (cond->signal == NULL) {
    DeleteCriticalSection(&cond->lock);
    return -1;
  }

  cond->broadcast = CreateEventA(NULL, TRUE, FALSE, NULL);

  if (cond->broadcast == NULL) {
    DeleteCriticalSection(&cond->lock);
    CloseHandle(cond->broadcast);
    return -1;
  }

  return 0;
}

RDB_UNUSED static int
pthread_cond_destroy(pthread_cond_t *cond) {
  int ret = 0;

  if (!CloseHandle(cond->broadcast))
    ret = -1;

  if (!CloseHandle(cond->signal))
    ret = -1;

  DeleteCriticalSection(&cond->lock);

  return ret;
}

RDB_UNUSED static int
pthread_cond_signal(pthread_cond_t *cond) {
  int have_waiters;

  EnterCriticalSection(&cond->lock);
  have_waiters = (cond->waiters > 0);
  LeaveCriticalSection(&cond->lock);

  if (have_waiters)
    SetEvent(cond->signal);

  return 0;
}

RDB_UNUSED static int
pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex) {
  HANDLE handles[2];
  int last_waiter;
  DWORD result;

  handles[0] = cond->signal;
  handles[1] = cond->broadcast;

  EnterCriticalSection(&cond->lock);
  cond->waiters++;
  LeaveCriticalSection(&cond->lock);

  LeaveCriticalSection(&mutex->lock);

  result = WaitForMultipleObjects(2, handles, FALSE, INFINITE);

  EnterCriticalSection(&cond->lock);
  cond->waiters--;
  last_waiter = (result == WAIT_OBJECT_0 + 1 && cond->waiters == 0);
  LeaveCriticalSection(&cond->lock);

  if (last_waiter)
    ResetEvent(cond->broadcast);

  EnterCriticalSection(&mutex->lock);

  if (result == WAIT_OBJECT_0 || result == WAIT_OBJECT_0 + 1)
    return 0;

  return -1;
}

static DWORD WINAPI /* __stdcall */
rdb_thread_run(void *ptr) {
  rdb_args_t args = *((rdb_args_t *)ptr);

  free(ptr);

  args.start(args.arg);

  return ERROR_SUCCESS;
}

RDB_UNUSED static int
pthread_create(pthread_t *thread,
               const pthread_attr_t *attr,
               void *(*start)(void *),
               void *arg) {
  rdb_args_t *args = malloc(sizeof(rdb_args_t));

  (void)attr;

  if (args == NULL)
    return -1;

  args->start = start;
  args->arg = arg;

  *thread = CreateThread(NULL, 0, rdb_thread_run, args, 0, NULL);

  if (*thread == NULL)
    return -1;

  return 0;
}

RDB_UNUSED static int
pthread_detach(pthread_t thread) {
  if (CloseHandle(thread) == FALSE)
    return -1;
  return 0;
}

RDB_UNUSED static int
pthread_join(pthread_t thread, void **retval) {
  (void)retval;

  WaitForSingleObject(thread, INFINITE);

  if (CloseHandle(thread) == FALSE)
    return -1;

  return 0;
}

#endif /* RDB_WIN_H */
