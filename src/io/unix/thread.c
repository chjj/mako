/*!
 * thread.c - posix threads for libsatoshi
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <errno.h>
#include <limits.h> /* PTHREAD_STACK_MIN */
#include <stdlib.h>
#include <string.h>
#include <unistd.h> /* sysconf, getpagesize */
#include <pthread.h>
#include <io/core.h>

#if defined(__APPLE__) || defined(__linux__)
#  include <sys/resource.h> /* getrlimit */
#endif

/*
 * Compat
 */

#undef HAVE_SYSCTL

#if defined(__APPLE__)     \
 || defined(__FreeBSD__)   \
 || defined(__OpenBSD__)   \
 || defined(__NetBSD__)    \
 || defined(__DragonFly__)
#  include <sys/types.h>
#  include <sys/sysctl.h>
#  if defined(CTL_HW) && (defined(HW_AVAILCPU) || defined(HW_NCPU))
#    define HAVE_SYSCTL
#  endif
#elif defined(__hpux)
#  include <sys/mpctl.h>
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

struct btc_thread_s {
  pthread_t handle;
};

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
btc_cond_timedwait(btc_cond_t *cond,
                   btc_mutex_t *mtx,
                   const btc_timespec_t *timeout) {
  struct timespec ts;
  int ret;

  memset(&ts, 0, sizeof(ts));

  ts.tv_sec = timeout->tv_sec;
  ts.tv_nsec = timeout->tv_nsec;

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

void
btc_thread_create(btc_thread_t *thread, void *(*start)(void *), void *arg) {
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

  if (pthread_create(&thread->handle, attr, start, arg) != 0)
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

/*
 * System
 */

#ifdef HAVE_SYSCTL
static int
try_sysctl(int name) {
  int ret = -1;
  size_t len;
  int mib[4];

  len = sizeof(ret);

  mib[0] = CTL_HW;
  mib[1] = name;

  if (sysctl(mib, 2, &ret, &len, NULL, 0) != 0)
    return -1;

  return ret;
}
#endif

int
btc_sys_cpu_count(void) {
  /* https://stackoverflow.com/questions/150355 */
#if defined(__linux__) || defined(__sun) || defined(_AIX)
  /* Linux, Solaris, AIX */
# if defined(_SC_NPROCESSORS_ONLN)
  return (int)sysconf(_SC_NPROCESSORS_ONLN);
# else
  return -1;
# endif
#elif defined(HAVE_SYSCTL)
  /* Apple, FreeBSD, OpenBSD, NetBSD, DragonFly BSD */
  int ret = -1;
# if defined(HW_AVAILCPU)
  ret = try_sysctl(HW_AVAILCPU);
# endif
# if defined(HW_NCPU)
  if (ret < 1)
    ret = try_sysctl(HW_NCPU);
# endif
  return ret;
#elif defined(__hpux)
  /* HP-UX */
  return mpctl(MPC_GETNUMSPUS, NULL, NULL);
#elif defined(__sgi)
  /* IRIX */
# if defined(_SC_NPROC_ONLN)
  return (int)sysconf(_SC_NPROC_ONLN);
# else
  return -1;
# endif
#else
  return -1;
#endif
}
