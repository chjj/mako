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

struct btc_mutex_s {
#if defined(HAVE_PTHREAD)
  pthread_mutex_t handle;
#else
  void *unused;
#endif
};

struct btc_rwlock_s {
#if defined(HAVE_PTHREAD)
  pthread_rwlock_t handle;
#else
  void *unused;
#endif
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

#ifdef HAVE_PTHREAD
  if (pthread_mutex_init(&mtx->handle, NULL) != 0)
    abort();
#endif

  return mtx;
}

void
btc_mutex_destroy(btc_mutex_t *mtx) {
#ifdef HAVE_PTHREAD
  if (pthread_mutex_destroy(&mtx->handle) != 0)
    abort();
#endif

  free(mtx);
}

void
btc_mutex_lock(btc_mutex_t *mtx) {
  (void)mtx;
#ifdef HAVE_PTHREAD
  if (pthread_mutex_lock(&mtx->handle) != 0)
    abort();
#endif
}

void
btc_mutex_unlock(btc_mutex_t *mtx) {
  (void)mtx;
#ifdef HAVE_PTHREAD
  if (pthread_mutex_unlock(&mtx->handle) != 0)
    abort();
#endif
}

/*
 * Read-Write Lock
 */

btc_rwlock_t *
btc_rwlock_create(void) {
  btc_rwlock_t *mtx = (btc_rwlock_t *)malloc(sizeof(btc_rwlock_t));

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
btc_rwlock_destroy(btc_rwlock_t *mtx) {
#ifdef HAVE_PTHREAD
  if (pthread_rwlock_destroy(&mtx->handle) != 0)
    abort();
#endif

  free(mtx);
}

void
btc_rwlock_wrlock(btc_rwlock_t *mtx) {
  (void)mtx;
#ifdef HAVE_PTHREAD
  if (pthread_rwlock_wrlock(&mtx->handle) != 0)
    abort();
#endif
}

void
btc_rwlock_wrunlock(btc_rwlock_t *mtx) {
  (void)mtx;
#ifdef HAVE_PTHREAD
  if (pthread_rwlock_unlock(&mtx->handle) != 0)
    abort();
#endif
}

void
btc_rwlock_rdlock(btc_rwlock_t *mtx) {
  (void)mtx;
#ifdef HAVE_PTHREAD
  if (pthread_rwlock_rdlock(&mtx->handle) != 0)
    abort();
#endif
}

void
btc_rwlock_rdunlock(btc_rwlock_t *mtx) {
  (void)mtx;
#ifdef HAVE_PTHREAD
  if (pthread_rwlock_unlock(&mtx->handle) != 0)
    abort();
#endif
}
