/*!
 * port_win_impl.h - windows port for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on libuv/libuv:
 *   Copyright (c) 2015-2020, libuv project contributors (MIT License).
 *   https://github.com/libuv/libuv
 */

#define LDB_NEED_WINDOWS_H

#include <assert.h>
#include <stdlib.h>
#include <string.h>
/* #include <windows.h> */
#include "internal.h"
#include "port.h"

/*
 * Types
 */

typedef struct ldb_args_s {
  void (*start)(void *);
  void *arg;
} ldb_args_t;

/*
 * Mutex
 */

static void
ldb_mutex_tryinit(ldb_mutex_t *mtx) {
  /* Logic from libsodium/core.c */
  long state;

  while ((state = InterlockedCompareExchange(&mtx->state, 1, 0)) == 1)
    Sleep(0);

  if (state == 0) {
    InitializeCriticalSection(&mtx->handle);

    if (InterlockedExchange(&mtx->state, 2) != 1)
      abort(); /* LCOV_EXCL_LINE */
  } else {
    assert(state == 2);
  }
}

void
ldb_mutex_init(ldb_mutex_t *mtx) {
  mtx->state = 2;
  InitializeCriticalSection(&mtx->handle);
}

void
ldb_mutex_destroy(ldb_mutex_t *mtx) {
  DeleteCriticalSection(&mtx->handle);
}

void
ldb_mutex_lock(ldb_mutex_t *mtx) {
  ldb_mutex_tryinit(mtx);
  EnterCriticalSection(&mtx->handle);
}

void
ldb_mutex_unlock(ldb_mutex_t *mtx) {
  LeaveCriticalSection(&mtx->handle);
}

/*
 * Conditional
 */

void
ldb_cond_init(ldb_cond_t *cond) {
  cond->waiters = 0;

  InitializeCriticalSection(&cond->lock);

  cond->signal = CreateEventA(NULL, FALSE, FALSE, NULL);
  cond->broadcast = CreateEventA(NULL, TRUE, FALSE, NULL);

  if (!cond->signal || !cond->broadcast)
    abort(); /* LCOV_EXCL_LINE */
}

void
ldb_cond_destroy(ldb_cond_t *cond) {
  if (!CloseHandle(cond->broadcast))
    abort(); /* LCOV_EXCL_LINE */

  if (!CloseHandle(cond->signal))
    abort(); /* LCOV_EXCL_LINE */

  DeleteCriticalSection(&cond->lock);
}

void
ldb_cond_signal(ldb_cond_t *cond) {
  int have_waiters;

  EnterCriticalSection(&cond->lock);
  have_waiters = (cond->waiters > 0);
  LeaveCriticalSection(&cond->lock);

  if (have_waiters)
    SetEvent(cond->signal);
}

void
ldb_cond_broadcast(ldb_cond_t *cond) {
  int have_waiters;

  EnterCriticalSection(&cond->lock);
  have_waiters = (cond->waiters > 0);
  LeaveCriticalSection(&cond->lock);

  if (have_waiters)
    SetEvent(cond->broadcast);
}

void
ldb_cond_wait(ldb_cond_t *cond, ldb_mutex_t *mtx) {
  HANDLE handles[2];
  int last_waiter;
  DWORD result;

  handles[0] = cond->signal;
  handles[1] = cond->broadcast;

  EnterCriticalSection(&cond->lock);
  cond->waiters++;
  LeaveCriticalSection(&cond->lock);

  LeaveCriticalSection(&mtx->handle);

  result = WaitForMultipleObjects(2, handles, FALSE, INFINITE);

  if (result != WAIT_OBJECT_0 && result != WAIT_OBJECT_0 + 1)
    abort(); /* LCOV_EXCL_LINE */

  EnterCriticalSection(&cond->lock);
  cond->waiters--;
  last_waiter = (result == WAIT_OBJECT_0 + 1 && cond->waiters == 0);
  LeaveCriticalSection(&cond->lock);

  if (last_waiter)
    ResetEvent(cond->broadcast);

  EnterCriticalSection(&mtx->handle);
}

/*
 * Thread
 */

static DWORD WINAPI /* __stdcall */
ldb_thread_run(void *ptr) {
  ldb_args_t args = *((ldb_args_t *)ptr);

  ldb_free(ptr);

  args.start(args.arg);

  return ERROR_SUCCESS;
}

void
ldb_thread_create(ldb_thread_t *thread, void (*start)(void *), void *arg) {
  ldb_args_t *args = ldb_malloc(sizeof(ldb_args_t));

  args->start = start;
  args->arg = arg;

  thread->handle = CreateThread(NULL, 0, ldb_thread_run, args, 0, NULL);

  if (thread->handle == NULL)
    abort(); /* LCOV_EXCL_LINE */
}

void
ldb_thread_detach(ldb_thread_t *thread) {
  if (!CloseHandle(thread->handle))
    abort(); /* LCOV_EXCL_LINE */
}

void
ldb_thread_join(ldb_thread_t *thread) {
  WaitForSingleObject(thread->handle, INFINITE);

  if (!CloseHandle(thread->handle))
    abort(); /* LCOV_EXCL_LINE */
}
