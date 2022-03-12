/*!
 * thread_pool.c - thread pool for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 */

#include <stdlib.h>
#include <string.h>
#include "internal.h"
#include "port.h"
#include "thread_pool.h"

/*
 * Work
 */

typedef struct ldb_work_s {
  ldb_work_f *func;
  void *arg;
  struct ldb_work_s *next;
} ldb_work_t;

static ldb_work_t *
ldb_work_create(ldb_work_f *func, void *arg) {
  ldb_work_t *work = ldb_malloc(sizeof(ldb_work_t));

  work->func = func;
  work->arg = arg;
  work->next = NULL;

  return work;
}

static ldb_work_t *
ldb_work_destroy(ldb_work_t *work) {
  ldb_work_t *next = work->next;
  ldb_free(work);
  return next;
}

static ldb_work_t *
ldb_work_execute(ldb_work_t *work) {
  work->func(work->arg);
  return ldb_work_destroy(work);
}

/*
 * Work Queue
 */

typedef struct ldb_queue_s {
  ldb_work_t *head;
  ldb_work_t *tail;
  int length;
} ldb_queue_t;

static void
ldb_queue_init(ldb_queue_t *queue) {
  queue->head = NULL;
  queue->tail = NULL;
  queue->length = 0;
}

static void
ldb_queue_clear(ldb_queue_t *queue) {
  ldb_work_t *work, *next;

  for (work = queue->head; work != NULL; work = next)
    next = ldb_work_destroy(work);

  ldb_queue_init(queue);
}

static void
ldb_queue_push(ldb_queue_t *queue, ldb_work_f *func, void *arg) {
  ldb_work_t *work = ldb_work_create(func, arg);

  if (queue->head == NULL)
    queue->head = work;

  if (queue->tail != NULL)
    queue->tail->next = work;

  queue->tail = work;
  queue->length++;
}

static ldb_work_t *
ldb_queue_shift(ldb_queue_t *queue) {
  ldb_work_t *work = queue->head;

  if (work == NULL)
    abort(); /* LCOV_EXCL_LINE */

  queue->head = work->next;

  if (queue->head == NULL)
    queue->tail = NULL;

  queue->length--;

  work->next = NULL;

  return work;
}

/*
 * Workers
 */

struct ldb_pool_s {
  ldb_mutex_t mutex;
  ldb_cond_t master;
  ldb_cond_t worker;
  ldb_queue_t queue;
  int threads;
  int running;
  int left;
  int stop;
};

static void
worker_thread(void *arg);

ldb_pool_t *
ldb_pool_create(int threads) {
  ldb_pool_t *pool = ldb_malloc(sizeof(ldb_pool_t));

  if (threads < 1)
    threads = 1;

  ldb_mutex_init(&pool->mutex);
  ldb_cond_init(&pool->master);
  ldb_cond_init(&pool->worker);
  ldb_queue_init(&pool->queue);

  pool->threads = threads;
  pool->running = 0;
  pool->left = 0;
  pool->stop = 0;

  return pool;
}

void
ldb_pool_destroy(ldb_pool_t *pool) {
  ldb_mutex_lock(&pool->mutex);

  ldb_queue_clear(&pool->queue);

  pool->stop = 1;

  ldb_cond_broadcast(&pool->worker);
  ldb_mutex_unlock(&pool->mutex);

  ldb_mutex_lock(&pool->mutex);

  while (pool->running > 0)
    ldb_cond_wait(&pool->master, &pool->mutex);

  ldb_mutex_unlock(&pool->mutex);

  ldb_mutex_destroy(&pool->mutex);
  ldb_cond_destroy(&pool->worker);
  ldb_cond_destroy(&pool->master);

  ldb_free(pool);
}

void
ldb_pool_schedule(ldb_pool_t *pool, ldb_work_f *func, void *arg) {
#if defined(_WIN32) || defined(LDB_PTHREAD)
  ldb_mutex_lock(&pool->mutex);

  if (pool->running == 0) {
    ldb_thread_t thread;
    int i;

    pool->running = pool->threads;

    for (i = 0; i < pool->threads; i++) {
      ldb_thread_create(&thread, worker_thread, pool);
      ldb_thread_detach(&thread);
    }
  }

  ldb_queue_push(&pool->queue, func, arg);

  pool->left++;

  ldb_cond_signal(&pool->worker);
  ldb_mutex_unlock(&pool->mutex);
#else
  (void)ldb_queue_push;
  (void)worker_thread;
  (void)pool;

  func(arg);
#endif
}

void
ldb_pool_wait(ldb_pool_t *pool) {
  ldb_mutex_lock(&pool->mutex);

  while (pool->left > 0)
    ldb_cond_wait(&pool->master, &pool->mutex);

  ldb_mutex_unlock(&pool->mutex);
}

static void
worker_thread(void *arg) {
  ldb_pool_t *pool = arg;
  ldb_work_t *work;
  int ran = 0;

  for (;;) {
    ldb_mutex_lock(&pool->mutex);

    if (ran) {
      pool->left--;

      if (!pool->stop && pool->left == 0)
        ldb_cond_signal(&pool->master);
    }

    while (!pool->stop && pool->queue.length == 0)
      ldb_cond_wait(&pool->worker, &pool->mutex);

    if (pool->stop)
      break;

    work = ldb_queue_shift(&pool->queue);
    ran = 1;

    ldb_mutex_unlock(&pool->mutex);

    ldb_work_execute(work);
  }

  if (--pool->running == 0)
    ldb_cond_signal(&pool->master);

  ldb_mutex_unlock(&pool->mutex);
}
