/*!
 * workers.c - thread pool for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 *
 * Resources:
 *   https://nachtimwald.com/2019/04/12/thread-pool-in-c/
 */

#include <stdlib.h>
#include <string.h>
#include <io/core.h>
#include <io/workers.h>

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
 * Work
 */

static btc_work_t *
btc_work_create(btc_work_f *func, void *arg) {
  btc_work_t *work = safe_malloc(sizeof(btc_work_t));

  work->func = func;
  work->arg = arg;
  work->next = NULL;

  return work;
}

static void
btc_work_destroy(btc_work_t *work) {
  free(work);
}

/*
 * Work Queue
 */

void
btc_workq_init(btc_workq_t *queue) {
  queue->head = NULL;
  queue->tail = NULL;
}

void
btc_workq_clear(btc_workq_t *queue) {
  btc_work_t *work, *next;

  for (work = queue->head; work != NULL; work = next) {
    next = work->next;
    btc_work_destroy(work);
  }

  queue->head = NULL;
  queue->tail = NULL;
}

void
btc_workq_push(btc_workq_t *queue, btc_work_f *func, void *arg) {
  btc_work_t *work = btc_work_create(func, arg);

  if (queue->head == NULL)
    queue->head = work;

  if (queue->tail != NULL)
    queue->tail->next = work;

  queue->tail = work;
}

static void
btc_workq_append(btc_workq_t *queue, btc_workq_t *batch) {
  if (queue->head == NULL) {
    queue->head = batch->head;
    queue->tail = batch->tail;
  } else {
    queue->tail->next = batch->head;
    queue->tail = batch->head;
  }
}

static btc_work_t *
btc_workq_shift(btc_workq_t *queue) {
  btc_work_t *work = queue->head;

  if (work == NULL)
    abort(); /* LCOV_EXCL_LINE */

  queue->head = work->next;

  if (queue->head == NULL)
    queue->tail = NULL;

  return work;
}

/*
 * Workers
 */

struct btc_workers_s {
  btc_mutex_t *mutex;
  btc_cond_t *master;
  btc_cond_t *worker;
  btc_workq_t queue;
  int threads;
  int count;
  int stop;
};

static void *
worker_thread(void *arg);

btc_workers_t *
btc_workers_create(int length) {
  btc_workers_t *pool = safe_malloc(sizeof(btc_workers_t));
  btc_thread_t *thread = btc_thread_alloc();
  int i;

  if (length < 2)
    length = 2;

  pool->mutex = btc_mutex_create();
  pool->master = btc_cond_create();
  pool->worker = btc_cond_create();

  btc_workq_init(&pool->queue);

  pool->threads = length;
  pool->count = 0;
  pool->stop = 0;

  for (i = 0; i < length; i++) {
    btc_thread_create(thread, worker_thread, pool);
    btc_thread_detach(thread);
  }

  btc_thread_free(thread);

  return pool;
}

void
btc_workers_destroy(btc_workers_t *pool) {
  btc_mutex_lock(pool->mutex);

  btc_workq_clear(&pool->queue);

  pool->stop = 1;

  btc_cond_broadcast(pool->worker);
  btc_mutex_unlock(pool->mutex);

  btc_mutex_lock(pool->mutex);

  while (pool->threads > 0)
    btc_cond_wait(pool->master, pool->mutex);

  btc_mutex_unlock(pool->mutex);

  btc_mutex_destroy(pool->mutex);
  btc_cond_destroy(pool->worker);
  btc_cond_destroy(pool->master);

  free(pool);
}

void
btc_workers_add(btc_workers_t *pool, btc_work_f *func, void *arg) {
  btc_mutex_lock(pool->mutex);
  btc_workq_push(&pool->queue, func, arg);
  btc_cond_signal(pool->worker);
  btc_mutex_unlock(pool->mutex);
}

void
btc_workers_batch(btc_workers_t *pool, btc_workq_t *batch) {
  if (batch->head == NULL)
    return;

  btc_mutex_lock(pool->mutex);

  btc_workq_append(&pool->queue, batch);

  if (batch->head == batch->tail)
    btc_cond_signal(pool->worker);
  else
    btc_cond_broadcast(pool->worker);

  batch->head = NULL;
  batch->tail = NULL;

  btc_mutex_unlock(pool->mutex);
}

void
btc_workers_wait(btc_workers_t *pool) {
  btc_mutex_lock(pool->mutex);

  while (pool->count > 0 || pool->queue.head != NULL)
    btc_cond_wait(pool->master, pool->mutex);

  btc_mutex_unlock(pool->mutex);
}

static void *
worker_thread(void *arg) {
  btc_workers_t *pool = arg;
  btc_work_t *work;

  for (;;) {
    btc_mutex_lock(pool->mutex);

    while (pool->queue.head == NULL && !pool->stop)
      btc_cond_wait(pool->worker, pool->mutex);

    if (pool->stop)
      break;

    work = btc_workq_shift(&pool->queue);

    pool->count++;

    btc_mutex_unlock(pool->mutex);

    work->func(work->arg);

    btc_work_destroy(work);

    btc_mutex_lock(pool->mutex);

    pool->count--;

    if (!pool->stop && pool->count == 0 && pool->queue.head == NULL)
      btc_cond_signal(pool->master);

    btc_mutex_unlock(pool->mutex);
  }

  pool->threads--;

  btc_cond_signal(pool->master);
  btc_mutex_unlock(pool->mutex);

  return NULL;
}
