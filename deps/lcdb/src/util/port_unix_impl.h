/*!
 * port_unix_impl.h - unix port for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 */

#include <assert.h>
#include <limits.h> /* PTHREAD_STACK_MIN */
#include <stdlib.h>
#include <unistd.h> /* sysconf, getpagesize */
#include <pthread.h>
#include "internal.h"
#include "port.h"

/*
 * Structs
 */

typedef struct ldb_args_s {
  void (*start)(void *);
  void *arg;
} ldb_args_t;

/*
 * Mutex
 */

void
ldb_mutex_init(ldb_mutex_t *mtx) {
  if (pthread_mutex_init(&mtx->handle, NULL) != 0)
    abort(); /* LCOV_EXCL_LINE */
}

void
ldb_mutex_destroy(ldb_mutex_t *mtx) {
  if (pthread_mutex_destroy(&mtx->handle) != 0)
    abort(); /* LCOV_EXCL_LINE */
}

void
ldb_mutex_lock(ldb_mutex_t *mtx) {
  if (pthread_mutex_lock(&mtx->handle) != 0)
    abort(); /* LCOV_EXCL_LINE */
}

void
ldb_mutex_unlock(ldb_mutex_t *mtx) {
  if (pthread_mutex_unlock(&mtx->handle) != 0)
    abort(); /* LCOV_EXCL_LINE */
}

/*
 * Conditional
 */

void
ldb_cond_init(ldb_cond_t *cond) {
  if (pthread_cond_init(&cond->handle, NULL) != 0)
    abort(); /* LCOV_EXCL_LINE */
}

void
ldb_cond_destroy(ldb_cond_t *cond) {
  if (pthread_cond_destroy(&cond->handle) != 0)
    abort(); /* LCOV_EXCL_LINE */
}

void
ldb_cond_signal(ldb_cond_t *cond) {
  if (pthread_cond_signal(&cond->handle) != 0)
    abort(); /* LCOV_EXCL_LINE */
}

void
ldb_cond_broadcast(ldb_cond_t *cond) {
  if (pthread_cond_broadcast(&cond->handle) != 0)
    abort(); /* LCOV_EXCL_LINE */
}

void
ldb_cond_wait(ldb_cond_t *cond, ldb_mutex_t *mtx) {
  if (pthread_cond_wait(&cond->handle, &mtx->handle) != 0)
    abort(); /* LCOV_EXCL_LINE */
}

/*
 * Thread
 */

static size_t
ldb_thread_stack_size(void) {
#ifdef _SC_PAGESIZE
  long page_size = sysconf(_SC_PAGESIZE);
#else
  long page_size = getpagesize();
#endif
  long stack_size = (1 << 20);

#ifdef PTHREAD_STACK_MIN
  long stack_min = PTHREAD_STACK_MIN;

  if (stack_min > 0 && stack_size < stack_min)
    stack_size = stack_min;
#endif

  if (page_size > 0 && (stack_size % page_size) != 0) {
    stack_size += (page_size - (stack_size % page_size));

    assert((stack_size % page_size) == 0);
  }

  return stack_size;
}

static void *
ldb_thread_run(void *ptr) {
  ldb_args_t args = *((ldb_args_t *)ptr);

  ldb_free(ptr);

  args.start(args.arg);

  return NULL;
}

void
ldb_thread_create(ldb_thread_t *thread, void (*start)(void *), void *arg) {
  ldb_args_t *args = ldb_malloc(sizeof(ldb_args_t));
  size_t stack_size = ldb_thread_stack_size();
  pthread_attr_t attr;

  args->start = start;
  args->arg = arg;

  if (pthread_attr_init(&attr) != 0)
    abort(); /* LCOV_EXCL_LINE */

  pthread_attr_setstacksize(&attr, stack_size);

  if (pthread_create(&thread->handle, &attr, ldb_thread_run, args) != 0)
    abort(); /* LCOV_EXCL_LINE */

  pthread_attr_destroy(&attr);
}

void
ldb_thread_detach(ldb_thread_t *thread) {
  if (pthread_detach(thread->handle) != 0)
    abort(); /* LCOV_EXCL_LINE */
}

void
ldb_thread_join(ldb_thread_t *thread) {
  if (pthread_join(thread->handle, NULL) != 0)
    abort(); /* LCOV_EXCL_LINE */
}
