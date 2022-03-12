/*!
 * port.h - ported functions for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 */

#ifndef LDB_PORT_H
#define LDB_PORT_H

#include <stddef.h>
#include "internal.h"

/*
 * Compat
 */

#if defined(LDB_NEED_WINDOWS_H)
#  include <windows.h>
#  define LDB_HANDLE HANDLE
#  define LDB_CRITICAL_SECTION CRITICAL_SECTION
#elif defined(_WIN32)
typedef void *LDB_HANDLE;
#  pragma pack(push, 8)
typedef struct LDB_RTL_CRITICAL_SECTION {
  void *DebugInfo;
  long LockCount;
  long RecursionCount;
  void *OwningThread;
  void *LockSemaphore;
#ifdef _WIN64
  unsigned __int64 SpinCount;
#else
  unsigned long SpinCount;
#endif
} LDB_CRITICAL_SECTION;
#  pragma pack(pop)
#elif defined(LDB_PTHREAD)
#  include <pthread.h>
#endif

/*
 * Types
 */

#if defined(_WIN32)

typedef struct ldb_mutex_s {
  volatile long state;
  LDB_CRITICAL_SECTION handle;
} ldb_mutex_t;

typedef struct ldb_cond_s {
  int waiters;
  LDB_HANDLE signal;
  LDB_HANDLE broadcast;
  LDB_CRITICAL_SECTION lock;
} ldb_cond_t;

typedef struct ldb_thread_s {
  LDB_HANDLE handle;
} ldb_thread_t;

#define LDB_MUTEX_INITIALIZER {0, {0, 0, 0, 0, 0, 0}}

#elif defined(LDB_PTHREAD)

typedef struct ldb_mutex_s {
  pthread_mutex_t handle;
} ldb_mutex_t;

typedef struct ldb_cond_s {
  pthread_cond_t handle;
} ldb_cond_t;

typedef struct ldb_thread_s {
  pthread_t handle;
} ldb_thread_t;

#define LDB_MUTEX_INITIALIZER { PTHREAD_MUTEX_INITIALIZER }

#else /* !LDB_PTHREAD */

typedef struct ldb_mutex_s {
  void *handle;
} ldb_mutex_t;

typedef struct ldb_cond_s {
  void *handle;
} ldb_cond_t;

typedef struct ldb_thread_s {
  void *handle;
} ldb_thread_t;

#define LDB_MUTEX_INITIALIZER {0}

#endif /* !LDB_PTHREAD */

/*
 * Mutex
 */

void
ldb_mutex_init(ldb_mutex_t *mtx);

void
ldb_mutex_destroy(ldb_mutex_t *mtx);

void
ldb_mutex_lock(ldb_mutex_t *mtx);

void
ldb_mutex_unlock(ldb_mutex_t *mtx);

/*
 * Conditional
 */

void
ldb_cond_init(ldb_cond_t *cond);

void
ldb_cond_destroy(ldb_cond_t *cond);

void
ldb_cond_signal(ldb_cond_t *cond);

void
ldb_cond_broadcast(ldb_cond_t *cond);

void
ldb_cond_wait(ldb_cond_t *cond, ldb_mutex_t *mtx);

/*
 * Thread
 */

void
ldb_thread_create(ldb_thread_t *thread, void (*start)(void *), void *arg);

void
ldb_thread_detach(ldb_thread_t *thread);

void
ldb_thread_join(ldb_thread_t *thread);

#endif /* LDB_PORT_H */
