/*!
 * thread.c - posix threads for mako
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <errno.h>
#include <limits.h> /* PTHREAD_STACK_MIN */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> /* getpagesize */
#include <pthread.h>
#include <io/core.h>

#if defined(__APPLE__) || defined(__linux__)
#  include <sys/resource.h> /* getrlimit */
#endif

/*
 * Structs
 */

struct btc_mutex_s {
  pthread_mutex_t handle;
};

struct btc_rwlock_s {
  pthread_rwlock_t handle;
};

struct btc_cond_s {
  pthread_cond_t handle;
};

struct btc_args_s {
  void (*start)(void *);
  void *arg;
};

struct btc_thread_s {
  pthread_t handle;
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

  if (pthread_mutex_init(&mtx->handle, NULL) != 0)
    abort(); /* LCOV_EXCL_LINE */

  return mtx;
}

void
btc_mutex_destroy(btc_mutex_t *mtx) {
  if (pthread_mutex_destroy(&mtx->handle) != 0)
    abort(); /* LCOV_EXCL_LINE */

  free(mtx);
}

void
btc_mutex_lock(btc_mutex_t *mtx) {
  if (pthread_mutex_lock(&mtx->handle) != 0)
    abort(); /* LCOV_EXCL_LINE */
}

void
btc_mutex_unlock(btc_mutex_t *mtx) {
  if (pthread_mutex_unlock(&mtx->handle) != 0)
    abort(); /* LCOV_EXCL_LINE */
}

int
btc_mutex_trylock(btc_mutex_t *mtx) {
  int ret = pthread_mutex_trylock(&mtx->handle);

  if (ret == EBUSY || ret == EAGAIN)
    return 0;

  if (ret != 0)
    abort(); /* LCOV_EXCL_LINE */

  return 1;
}

/*
 * Read-Write Lock
 */

btc_rwlock_t *
btc_rwlock_create(void) {
  btc_rwlock_t *mtx = safe_malloc(sizeof(btc_rwlock_t));

  if (pthread_rwlock_init(&mtx->handle, NULL) != 0)
    abort(); /* LCOV_EXCL_LINE */

  return mtx;
}

void
btc_rwlock_destroy(btc_rwlock_t *mtx) {
  if (pthread_rwlock_destroy(&mtx->handle) != 0)
    abort(); /* LCOV_EXCL_LINE */

  free(mtx);
}

void
btc_rwlock_wrlock(btc_rwlock_t *mtx) {
  if (pthread_rwlock_wrlock(&mtx->handle) != 0)
    abort(); /* LCOV_EXCL_LINE */
}

void
btc_rwlock_wrunlock(btc_rwlock_t *mtx) {
  if (pthread_rwlock_unlock(&mtx->handle) != 0)
    abort(); /* LCOV_EXCL_LINE */
}

void
btc_rwlock_rdlock(btc_rwlock_t *mtx) {
  if (pthread_rwlock_rdlock(&mtx->handle) != 0)
    abort(); /* LCOV_EXCL_LINE */
}

void
btc_rwlock_rdunlock(btc_rwlock_t *mtx) {
  if (pthread_rwlock_unlock(&mtx->handle) != 0)
    abort(); /* LCOV_EXCL_LINE */
}

int
btc_rwlock_trywrlock(btc_rwlock_t *mtx) {
  int ret = pthread_rwlock_trywrlock(&mtx->handle);

  if (ret == EBUSY || ret == EAGAIN)
    return 0;

  if (ret != 0)
    abort(); /* LCOV_EXCL_LINE */

  return 1;
}

int
btc_rwlock_tryrdlock(btc_rwlock_t *mtx) {
  int ret = pthread_rwlock_tryrdlock(&mtx->handle);

  if (ret == EBUSY || ret == EAGAIN)
    return 0;

  if (ret != 0)
    abort(); /* LCOV_EXCL_LINE */

  return 1;
}

/*
 * Conditional
 */

btc_cond_t *
btc_cond_create(void) {
  btc_cond_t *cond = safe_malloc(sizeof(btc_cond_t));

  if (pthread_cond_init(&cond->handle, NULL) != 0)
    abort(); /* LCOV_EXCL_LINE */

  return cond;
}

void
btc_cond_destroy(btc_cond_t *cond) {
  if (pthread_cond_destroy(&cond->handle) != 0)
    abort(); /* LCOV_EXCL_LINE */

  free(cond);
}

void
btc_cond_signal(btc_cond_t *cond) {
  if (pthread_cond_signal(&cond->handle) != 0)
    abort(); /* LCOV_EXCL_LINE */
}

void
btc_cond_broadcast(btc_cond_t *cond) {
  if (pthread_cond_broadcast(&cond->handle) != 0)
    abort(); /* LCOV_EXCL_LINE */
}

void
btc_cond_wait(btc_cond_t *cond, btc_mutex_t *mtx) {
  if (pthread_cond_wait(&cond->handle, &mtx->handle) != 0)
    abort(); /* LCOV_EXCL_LINE */
}

int
btc_cond_timedwait(btc_cond_t *cond, btc_mutex_t *mtx, int64_t msec) {
  struct timespec ts;
  int ret;

  memset(&ts, 0, sizeof(ts));

  if (msec < 0)
    abort(); /* LCOV_EXCL_LINE */

  ts.tv_sec = msec / 1000;
  ts.tv_nsec = (msec % 1000) * 1000000;

  ret = pthread_cond_timedwait(&cond->handle, &mtx->handle, &ts);

  if (ret == ETIMEDOUT)
    return 0;

  if (ret != 0)
    abort(); /* LCOV_EXCL_LINE */

  return 1;
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

/* Set a sane stack size for thread (from libuv). */
#if defined(__APPLE__) || defined(__linux__)
static size_t
thread_stack_size(void) {
  struct rlimit lim;

  if (getrlimit(RLIMIT_STACK, &lim) != 0)
    abort(); /* LCOV_EXCL_LINE */

  if (lim.rlim_cur != RLIM_INFINITY) {
    lim.rlim_cur -= (lim.rlim_cur % (rlim_t)getpagesize());

    if (lim.rlim_cur >= PTHREAD_STACK_MIN)
      return lim.rlim_cur;
  }

#if !defined(__linux__)
  return 0;
#elif defined(__PPC__) || defined(__ppc__) || defined(__powerpc__)
  return 4 << 20;
#else
  return 2 << 20;
#endif
}
#endif

static void *
btc_thread_run(void *ptr) {
  btc_args_t args = *((btc_args_t *)ptr);

  free(ptr);

  args.start(args.arg);

  return NULL;
}

void
btc_thread_create(btc_thread_t *thread, void (*start)(void *), void *arg) {
  btc_args_t *args = safe_malloc(sizeof(btc_args_t));
  pthread_attr_t *attr = NULL;

#if defined(__APPLE__) || defined(__linux__)
  size_t stack_size = thread_stack_size();
  pthread_attr_t tmp;

  if (stack_size > 0) {
    attr = &tmp;

    if (pthread_attr_init(attr) != 0)
      abort(); /* LCOV_EXCL_LINE */

    if (pthread_attr_setstacksize(attr, stack_size) != 0)
      abort(); /* LCOV_EXCL_LINE */
  }
#endif

  args->start = start;
  args->arg = arg;

  if (pthread_create(&thread->handle, attr, btc_thread_run, args) != 0)
    abort(); /* LCOV_EXCL_LINE */
}

void
btc_thread_detach(btc_thread_t *thread) {
  if (pthread_detach(thread->handle) != 0)
    abort(); /* LCOV_EXCL_LINE */
}

void
btc_thread_join(btc_thread_t *thread) {
  if (pthread_join(thread->handle, NULL) != 0)
    abort(); /* LCOV_EXCL_LINE */
}

/*
 * Once
 */

void
btc_once(btc_once_t *guard, void (*callback)(void)) {
  if (pthread_once(guard, callback) != 0)
    abort(); /* LCOV_EXCL_LINE */
}

/*
 * TLS
 */

void
btc_tls_init(btc_tls_t *key) {
  if (pthread_key_create(key, NULL) != 0)
    abort(); /* LCOV_EXCL_LINE */
}

void
btc_tls_clear(btc_tls_t *key) {
  if (pthread_key_delete(*key) != 0)
    abort(); /* LCOV_EXCL_LINE */
}

void *
btc_tls_get(btc_tls_t *key) {
  return pthread_getspecific(*key);
}

void
btc_tls_set(btc_tls_t *key, void *value) {
  if (pthread_setspecific(*key, value) != 0)
    abort(); /* LCOV_EXCL_LINE */
}
