/*!
 * port_none_impl.h - no threads port for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 */

#include <stdlib.h>
#include "port.h"

/*
 * Mutex
 */

void
ldb_mutex_init(ldb_mutex_t *mtx) {
  (void)mtx;
}

void
ldb_mutex_destroy(ldb_mutex_t *mtx) {
  (void)mtx;
}

void
ldb_mutex_lock(ldb_mutex_t *mtx) {
  (void)mtx;
}

void
ldb_mutex_unlock(ldb_mutex_t *mtx) {
  (void)mtx;
}

/*
 * Conditional
 */

void
ldb_cond_init(ldb_cond_t *cond) {
  (void)cond;
}

void
ldb_cond_destroy(ldb_cond_t *cond) {
  (void)cond;
}

void
ldb_cond_signal(ldb_cond_t *cond) {
  (void)cond;
}

void
ldb_cond_broadcast(ldb_cond_t *cond) {
  (void)cond;
}

void
ldb_cond_wait(ldb_cond_t *cond, ldb_mutex_t *mtx) {
  (void)cond;
  (void)mtx;
  abort(); /* LCOV_EXCL_LINE */
}

/*
 * Thread
 */

void
ldb_thread_create(ldb_thread_t *thread, void (*start)(void *), void *arg) {
  (void)thread;
  (void)start;
  (void)arg;
  abort(); /* LCOV_EXCL_LINE */
}

void
ldb_thread_detach(ldb_thread_t *thread) {
  (void)thread;
}

void
ldb_thread_join(ldb_thread_t *thread) {
  (void)thread;
}
