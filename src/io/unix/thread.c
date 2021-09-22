/*!
 * thread.c - posix threads for libsatoshi
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#undef HAVE_PTHREAD

#if !defined(__EMSCRIPTEN__) && !defined(__wasi__)
#  define HAVE_PTHREAD
#endif

#include <stdlib.h>
#ifdef HAVE_PTHREAD
#include <pthread.h>
#endif
#include <io/core.h>

/*
 * Structs
 */

typedef struct btc_mutex_s {
#if defined(HAVE_PTHREAD)
  pthread_mutex_t handle;
#else
  void *unused;
#endif
} btc__mutex_t;

typedef struct btc_rwlock_s {
#if defined(HAVE_PTHREAD)
  pthread_rwlock_t handle;
#else
  void *unused;
#endif
} btc__rwlock_t;

/*
 * Mutex
 */

btc__mutex_t *
btc_mutex_create(void) {
  btc__mutex_t *mtx = (btc__mutex_t *)malloc(sizeof(btc__mutex_t));

  if (mtx == NULL) {
    abort();
    return NULL;
  }

#ifdef HAVE_PTHREAD
  if (pthread_mutex_init(&mtx->handle, NULL) != 0)
    abort();
#endif

  return mtx;
}

void
btc_mutex_destroy(btc__mutex_t *mtx) {
#ifdef HAVE_PTHREAD
  if (pthread_mutex_destroy(&mtx->handle) != 0)
    abort();
#endif

  free(mtx);
}

void
btc_mutex_lock(btc__mutex_t *mtx) {
  (void)mtx;
#ifdef HAVE_PTHREAD
  if (pthread_mutex_lock(&mtx->handle) != 0)
    abort();
#endif
}

void
btc_mutex_unlock(btc__mutex_t *mtx) {
  (void)mtx;
#ifdef HAVE_PTHREAD
  if (pthread_mutex_unlock(&mtx->handle) != 0)
    abort();
#endif
}

/*
 * Read-Write Lock
 */

btc__rwlock_t *
btc_rwlock_create(void) {
  btc__rwlock_t *mtx = (btc__rwlock_t *)malloc(sizeof(btc__rwlock_t));

  if (mtx == NULL) {
    abort();
    return NULL;
  }

#ifdef HAVE_PTHREAD
  if (pthread_rwlock_init(&mtx->handle, NULL) != 0)
    abort();
#endif

  return mtx;
}

void
btc_rwlock_destroy(btc__rwlock_t *mtx) {
#ifdef HAVE_PTHREAD
  if (pthread_rwlock_destroy(&mtx->handle) != 0)
    abort();
#endif

  free(mtx);
}

void
btc_rwlock_wrlock(btc__rwlock_t *mtx) {
  (void)mtx;
#ifdef HAVE_PTHREAD
  if (pthread_rwlock_wrlock(&mtx->handle) != 0)
    abort();
#endif
}

void
btc_rwlock_wrunlock(btc__rwlock_t *mtx) {
  (void)mtx;
#ifdef HAVE_PTHREAD
  if (pthread_rwlock_unlock(&mtx->handle) != 0)
    abort();
#endif
}

void
btc_rwlock_rdlock(btc__rwlock_t *mtx) {
  (void)mtx;
#ifdef HAVE_PTHREAD
  if (pthread_rwlock_rdlock(&mtx->handle) != 0)
    abort();
#endif
}

void
btc_rwlock_rdunlock(btc__rwlock_t *mtx) {
  (void)mtx;
#ifdef HAVE_PTHREAD
  if (pthread_rwlock_unlock(&mtx->handle) != 0)
    abort();
#endif
}
