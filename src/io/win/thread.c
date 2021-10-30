/*!
 * thread.c - windows threads for libsatoshi
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 *
 * Parts of this software are based on libuv/libuv:
 *   Copyright (c) 2015-2020, libuv project contributors (MIT License).
 *   https://github.com/libuv/libuv
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <io/core.h>

/*
 * Compat
 */

#undef HAVE_COND_VAR

/* TODO: Should be Windows Vista */
#if (defined(_WIN32_WINNT) && _WIN32_WINNT >= 0x0601) /* Windows 7 (2009) */ \
 && (defined(_MSC_VER) && _MSC_VER >= 1600) /* VS 2010 */                    \
 && !defined(__MINGW32__)
#  define HAVE_COND_VAR
#endif

/*
 * Structs
 */

struct btc_mutex_s {
  CRITICAL_SECTION handle;
};

struct btc_rwlock_s {
  int readers;
  CRITICAL_SECTION readers_lock;
  HANDLE write_semaphore;
};

struct btc_cond_s {
#if defined(HAVE_COND_VAR)
  CONDITION_VARIABLE handle;
#else
  int waiters;
  CRITICAL_SECTION lock;
  HANDLE signal;
  HANDLE broadcast;
#endif
};

struct btc_args_s {
  void (*start)(void *);
  void *arg;
};

struct btc_thread_s {
  HANDLE handle;
};

/*
 * Types
 */

typedef struct btc_args_s btc_args_t;

/*
 * Helpers
 */

static void *
safe_malloc(size_t size) {
  void *ptr = malloc(size);

  if (ptr == NULL)
    abort(); /* LCOV_EXCL_LINE */

  return ptr;
}

/*
 * Mutex
 */

btc_mutex_t *
btc_mutex_create(void) {
  btc_mutex_t *mtx = safe_malloc(sizeof(btc_mutex_t));

  InitializeCriticalSection(&mtx->handle);

  return mtx;
}

void
btc_mutex_destroy(btc_mutex_t *mtx) {
  DeleteCriticalSection(&mtx->handle);
  free(mtx);
}

void
btc_mutex_lock(btc_mutex_t *mtx) {
  EnterCriticalSection(&mtx->handle);
}

void
btc_mutex_unlock(btc_mutex_t *mtx) {
  LeaveCriticalSection(&mtx->handle);
}

int
btc_mutex_trylock(btc_mutex_t *mtx) {
  if (TryEnterCriticalSection(&mtx->handle))
    return 1;

  return 0;
}

/*
 * Read-Write Lock
 */

btc_rwlock_t *
btc_rwlock_create(void) {
  btc_rwlock_t *mtx = safe_malloc(sizeof(btc_rwlock_t));
  HANDLE handle = CreateSemaphoreA(NULL, 1, 1, NULL);

  if (handle == NULL)
    abort(); /* LCOV_EXCL_LINE */

  mtx->write_semaphore = handle;

  InitializeCriticalSection(&mtx->readers_lock);

  mtx->readers = 0;

  return mtx;
}

void
btc_rwlock_destroy(btc_rwlock_t *mtx) {
  DeleteCriticalSection(&mtx->readers_lock);
  CloseHandle(mtx->write_semaphore);
  free(mtx);
}

void
btc_rwlock_wrlock(btc_rwlock_t *mtx) {
  DWORD r = WaitForSingleObject(mtx->write_semaphore, INFINITE);

  if (r != WAIT_OBJECT_0)
    abort(); /* LCOV_EXCL_LINE */
}

void
btc_rwlock_wrunlock(btc_rwlock_t *mtx) {
  if (!ReleaseSemaphore(mtx->write_semaphore, 1, NULL))
    abort(); /* LCOV_EXCL_LINE */
}

void
btc_rwlock_rdlock(btc_rwlock_t *mtx) {
  EnterCriticalSection(&mtx->readers_lock);

  if (++mtx->readers == 1) {
    DWORD r = WaitForSingleObject(mtx->write_semaphore, INFINITE);

    if (r != WAIT_OBJECT_0)
      abort(); /* LCOV_EXCL_LINE */
  }

  LeaveCriticalSection(&mtx->readers_lock);
}

void
btc_rwlock_rdunlock(btc_rwlock_t *mtx) {
  EnterCriticalSection(&mtx->readers_lock);

  if (--mtx->readers == 0) {
    if (!ReleaseSemaphore(mtx->write_semaphore, 1, NULL))
      abort(); /* LCOV_EXCL_LINE */
  }

  LeaveCriticalSection(&mtx->readers_lock);
}

int
btc_rwlock_trywrlock(btc_rwlock_t *mtx) {
  DWORD r = WaitForSingleObject(mtx->write_semaphore, 0);

  if (r == WAIT_TIMEOUT)
    return 0;

  if (r != WAIT_OBJECT_0)
    abort(); /* LCOV_EXCL_LINE */

  return 1;
}

int
btc_rwlock_tryrdlock(btc_rwlock_t *mtx) {
  int ret = 1;

  if (!TryEnterCriticalSection(&mtx->readers_lock))
    return 0;

  if (mtx->readers == 0) {
    DWORD r = WaitForSingleObject(mtx->write_semaphore, 0);

    if (r == WAIT_OBJECT_0)
      mtx->readers++;
    else if (r == WAIT_TIMEOUT)
      ret = 0;
    else if (r == WAIT_FAILED)
      abort(); /* LCOV_EXCL_LINE */
  } else {
    mtx->readers++;
  }

  LeaveCriticalSection(&mtx->readers_lock);

  return ret;
}

/*
 * Conditional
 */

btc_cond_t *
btc_cond_create(void) {
  btc_cond_t *cond = safe_malloc(sizeof(btc_cond_t));

#if defined(HAVE_COND_VAR)
  InitializeConditionVariable(&cond->handle);
#else
  cond->waiters = 0;

  InitializeCriticalSection(&cond->lock);

  cond->signal = CreateEvent(NULL, FALSE, FALSE, NULL);
  cond->broadcast = CreateEvent(NULL, TRUE, FALSE, NULL);

  if (!cond->signal || !cond->broadcast)
    abort(); /* LCOV_EXCL_LINE */
#endif

  return cond;
}

void
btc_cond_destroy(btc_cond_t *cond) {
#if defined(HAVE_COND_VAR)
  /* nothing */
#else
  if (!CloseHandle(cond->broadcast))
    abort(); /* LCOV_EXCL_LINE */

  if (!CloseHandle(cond->signal))
    abort(); /* LCOV_EXCL_LINE */

  DeleteCriticalSection(&cond->lock);
#endif

  free(cond);
}

void
btc_cond_signal(btc_cond_t *cond) {
#if defined(HAVE_COND_VAR)
  WakeConditionVariable(&cond->handle);
#else
  int have_waiters;

  EnterCriticalSection(&cond->lock);
  have_waiters = (cond->waiters > 0);
  LeaveCriticalSection(&cond->lock);

  if (have_waiters)
    SetEvent(cond->signal);
#endif
}

void
btc_cond_broadcast(btc_cond_t *cond) {
#if defined(HAVE_COND_VAR)
  WakeAllConditionVariable(&cond->handle);
#else
  int have_waiters;

  EnterCriticalSection(&cond->lock);
  have_waiters = (cond->waiters > 0);
  LeaveCriticalSection(&cond->lock);

  if (have_waiters)
    SetEvent(cond->broadcast);
#endif
}

#ifndef HAVE_COND_VAR
static int
cond_wait(btc_cond_t *cond, btc_mutex_t *mtx, DWORD timeout) {
  HANDLE handles[2];
  int last_waiter;
  DWORD result;

  handles[0] = cond->signal;
  handles[1] = cond->broadcast;

  EnterCriticalSection(&cond->lock);
  cond->waiters++;
  LeaveCriticalSection(&cond->lock);

  LeaveCriticalSection(&mtx->handle);

  result = WaitForMultipleObjects(2, handles, FALSE, timeout);

  EnterCriticalSection(&cond->lock);
  cond->waiters--;
  last_waiter = (result == WAIT_OBJECT_0 + 1 && cond->waiters == 0);
  LeaveCriticalSection(&cond->lock);

  if (last_waiter)
    ResetEvent(cond->broadcast);

  EnterCriticalSection(&mtx->handle);

  if (result == WAIT_OBJECT_0 || result == WAIT_OBJECT_0 + 1)
    return 1;

  if (result == WAIT_TIMEOUT)
    return 0;

  abort(); /* LCOV_EXCL_LINE */
  return 0; /* LCOV_EXCL_LINE */
}
#endif

void
btc_cond_wait(btc_cond_t *cond, btc_mutex_t *mtx) {
#if defined(HAVE_COND_VAR)
  if (!SleepConditionVariableCS(&cond->handle, &mtx->handle, INFINITE))
    abort(); /* LCOV_EXCL_LINE */
#else
  if (!cond_wait(cond, mtx, INFINITE))
    abort(); /* LCOV_EXCL_LINE */
#endif
}

int
btc_cond_timedwait(btc_cond_t *cond,
                   btc_mutex_t *mtx,
                   const btc_timespec_t *timeout) {
  DWORD ms = BTC_MSEC(timeout);

#if defined(HAVE_COND_VAR)
  if (SleepConditionVariableCS(&cond->handle, &mtx->handle, ms))
    return 1;

  if (GetLastError() != ERROR_TIMEOUT)
    abort(); /* LCOV_EXCL_LINE */

  return 0;
#else
  return cond_wait(cond, mtx, ms);
#endif
}

/*
 * Thread
 */

btc_thread_t *
btc_thread_alloc(void) {
  return safe_malloc(sizeof(btc_thread_t));
}

void
btc_thread_free(btc_thread_t *thread) {
  free(thread);
}

static DWORD WINAPI /* __stdcall */
btc_thread_run(void *ptr) {
  btc_args_t args = *((btc_args_t *)ptr);

  free(ptr);

  args.start(args.arg);

  return ERROR_SUCCESS;
}

void
btc_thread_create(btc_thread_t *thread, void (*start)(void *), void *arg) {
  btc_args_t *args = safe_malloc(sizeof(btc_args_t));

  args->start = start;
  args->arg = arg;

  thread->handle = CreateThread(NULL, 0, btc_thread_run, args, 0, NULL);

  if (thread->handle == NULL)
    abort(); /* LCOV_EXCL_LINE */
}

void
btc_thread_detach(btc_thread_t *thread) {
  if (CloseHandle(thread->handle) == FALSE)
    abort(); /* LCOV_EXCL_LINE */
}

void
btc_thread_join(btc_thread_t *thread) {
  WaitForSingleObject(thread->handle, INFINITE);

  if (CloseHandle(thread->handle) == FALSE)
    abort(); /* LCOV_EXCL_LINE */
}

/*
 * Once
 */

void
btc_once(btc_once_t *guard, void (*callback)(void)) {
  HANDLE created, existing;

  if (guard->ran)
    return;

  created = CreateEvent(NULL, 1, 0, NULL);

  if (created == NULL)
    abort(); /* LCOV_EXCL_LINE */

  existing = InterlockedCompareExchangePointer(&guard->event, created, NULL);

  if (existing == NULL) {
    callback();

    if (!SetEvent(created))
      abort(); /* LCOV_EXCL_LINE */

    guard->ran = 1;
  } else {
    CloseHandle(created);

    if (WaitForSingleObject(existing, INFINITE) != WAIT_OBJECT_0)
      abort(); /* LCOV_EXCL_LINE */
  }
}

/*
 * TLS
 */

void
btc_tls_init(btc_tls_t *key) {
  key->index = TlsAlloc();

  if (key->index == TLS_OUT_OF_INDEXES)
    abort(); /* LCOV_EXCL_LINE */
}

void
btc_tls_clear(btc_tls_t *key) {
  if (TlsFree(key->index) == FALSE)
    abort(); /* LCOV_EXCL_LINE */

  key->index = TLS_OUT_OF_INDEXES;
}

void *
btc_tls_get(btc_tls_t *key) {
  void *value = TlsGetValue(key->index);

  if (value == NULL) {
    if (GetLastError() != ERROR_SUCCESS)
      abort(); /* LCOV_EXCL_LINE */
  }

  return value;
}

void
btc_tls_set(btc_tls_t *key, void *value) {
  if (TlsSetValue(key->index, value) == FALSE)
    abort(); /* LCOV_EXCL_LINE */
}

/*
 * System
 */

int
btc_sys_cpu_count(void) {
  SYSTEM_INFO info;
  GetSystemInfo(&info);
  return info.dwNumberOfProcessors;
}
