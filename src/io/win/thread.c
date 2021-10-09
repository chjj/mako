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
 * Structs
 */

struct btc_mutex_s {
  CRITICAL_SECTION handle;
};

struct btc_rwlock_s {
  unsigned int readers;
  CRITICAL_SECTION readers_lock;
  HANDLE write_semaphore;
};

/*
 * Mutex
 */

btc_mutex_t *
btc_mutex_create(void) {
  btc_mutex_t *mtx = (btc_mutex_t *)malloc(sizeof(btc_mutex_t));

  if (mtx == NULL) {
    abort();
    return NULL;
  }

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

/*
 * Read-Write Lock
 */

btc_rwlock_t *
btc_rwlock_create(void) {
  btc_rwlock_t *mtx = (btc_rwlock_t *)malloc(sizeof(btc_rwlock_t));
  HANDLE handle;

  if (mtx == NULL) {
    abort();
    return NULL;
  }

  handle = CreateSemaphoreA(NULL, 1, 1, NULL);

  if (handle == NULL)
    abort();

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
    abort();
}

void
btc_rwlock_wrunlock(btc_rwlock_t *mtx) {
  if (!ReleaseSemaphore(mtx->write_semaphore, 1, NULL))
    abort();
}

void
btc_rwlock_rdlock(btc_rwlock_t *mtx) {
  EnterCriticalSection(&mtx->readers_lock);

  if (++mtx->readers == 1) {
    DWORD r = WaitForSingleObject(mtx->write_semaphore, INFINITE);

    if (r != WAIT_OBJECT_0)
      abort();
  }

  LeaveCriticalSection(&mtx->readers_lock);
}

void
btc_rwlock_rdunlock(btc_rwlock_t *mtx) {
  EnterCriticalSection(&mtx->readers_lock);

  if (--mtx->readers == 0) {
    if (!ReleaseSemaphore(mtx->write_semaphore, 1, NULL))
      abort();
  }

  LeaveCriticalSection(&mtx->readers_lock);
}
