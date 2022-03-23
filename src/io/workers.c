/*!
 * workers.c - thread pool for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
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

static btc_work_t *
btc_work_destroy(btc_work_t *work) {
  btc_work_t *next = work->next;
  free(work);
  return next;
}

static btc_work_t *
btc_work_execute(btc_work_t *work) {
  work->func(work->arg);
  return btc_work_destroy(work);
}

/*
 * Work Queue
 */

void
btc_workq_init(btc_workq_t *queue) {
  queue->head = NULL;
  queue->tail = NULL;
  queue->length = 0;
}

void
btc_workq_clear(btc_workq_t *queue) {
  btc_work_t *work, *next;

  for (work = queue->head; work != NULL; work = next)
    next = btc_work_destroy(work);

  btc_workq_init(queue);
}

void
btc_workq_push(btc_workq_t *queue, btc_work_f *func, void *arg) {
  btc_work_t *work = btc_work_create(func, arg);

  if (queue->head == NULL)
    queue->head = work;

  if (queue->tail != NULL)
    queue->tail->next = work;

  queue->tail = work;
  queue->length++;
}

static btc_work_t *
btc_workq_shift(btc_workq_t *queue) {
  btc_work_t *work = queue->head;

  if (work == NULL)
    abort(); /* LCOV_EXCL_LINE */

  queue->head = work->next;

  if (queue->head == NULL)
    queue->tail = NULL;

  queue->length--;

  work->next = NULL;

  return work;
}

static void
btc_workq_concat(btc_workq_t *z, btc_workq_t *x) {
  if (z->head == NULL) {
    z->head = x->head;
    z->tail = x->tail;
  } else {
    z->tail->next = x->head;
    z->tail = x->head;
  }

  z->length += x->length;

  btc_workq_init(x);
}

static void
btc_workq_slice(btc_workq_t *z, btc_workq_t *x, int length) {
  btc_work_t *work;

  if (length <= 0)
    abort(); /* LCOV_EXCL_LINE */

  length--;

  work = btc_workq_shift(x);

  z->head = work;
  z->tail = work;
  z->length = 1;

  while (length--) {
    work = btc_workq_shift(x);

    z->tail->next = work;
    z->tail = work;
    z->length++;
  }
}

/*
 * Workers
 */

struct btc_workers_s {
  btc_mutex_t mutex;
  btc_cond_t master;
  btc_cond_t worker;
  btc_workq_t queue;
  int threads;
  int max_batch;
  int idle;
  int left;
  int stop;
};

static void
worker_thread(void *arg);

btc_workers_t *
btc_workers_create(int threads, int max_batch) {
  btc_workers_t *pool = safe_malloc(sizeof(btc_workers_t));
  btc_thread_t thread;
  int i;

#if defined(_WIN32) || defined(BTC_PTHREAD)
  if (threads < 2)
    threads = 2;
#else
  threads = 0;
#endif

  if (max_batch < 1)
    max_batch = 1;

  btc_mutex_init(&pool->mutex);
  btc_cond_init(&pool->master);
  btc_cond_init(&pool->worker);

  btc_workq_init(&pool->queue);

  pool->threads = threads;
  pool->max_batch = max_batch;
  pool->idle = 0;
  pool->left = 0;
  pool->stop = 0;

  for (i = 0; i < threads; i++) {
    btc_thread_create(&thread, worker_thread, pool);
    btc_thread_detach(&thread);
  }

  return pool;
}

void
btc_workers_destroy(btc_workers_t *pool) {
  btc_mutex_lock(&pool->mutex);

  btc_workq_clear(&pool->queue);

  pool->stop = 1;

  btc_cond_broadcast(&pool->worker);
  btc_mutex_unlock(&pool->mutex);

  btc_mutex_lock(&pool->mutex);

  while (pool->threads > 0)
    btc_cond_wait(&pool->master, &pool->mutex);

  btc_mutex_unlock(&pool->mutex);

  btc_mutex_destroy(&pool->mutex);
  btc_cond_destroy(&pool->worker);
  btc_cond_destroy(&pool->master);

  free(pool);
}

void
btc_workers_add(btc_workers_t *pool, btc_work_f *func, void *arg) {
#if defined(_WIN32) || defined(BTC_PTHREAD)
  btc_mutex_lock(&pool->mutex);
  btc_workq_push(&pool->queue, func, arg);
  pool->left++;
  btc_cond_signal(&pool->worker);
  btc_mutex_unlock(&pool->mutex);
#else
  (void)pool;

  func(arg);
#endif
}

void
btc_workers_batch(btc_workers_t *pool, btc_workq_t *batch) {
#if defined(_WIN32) || defined(BTC_PTHREAD)
  int length = batch->length;

  if (length == 0)
    return;

  btc_mutex_lock(&pool->mutex);

  btc_workq_concat(&pool->queue, batch);

  pool->left += length;

  if (length == 1)
    btc_cond_signal(&pool->worker);
  else
    btc_cond_broadcast(&pool->worker);

  btc_mutex_unlock(&pool->mutex);
#else
  btc_work_t *work, *next;

  (void)btc_workq_concat;
  (void)pool;

  for (work = batch->head; work != NULL; work = next)
    next = btc_work_execute(work);

  btc_workq_init(batch);
#endif
}

void
btc_workers_wait(btc_workers_t *pool) {
  btc_mutex_lock(&pool->mutex);

  while (pool->left > 0)
    btc_cond_wait(&pool->master, &pool->mutex);

  btc_mutex_unlock(&pool->mutex);
}

static int
btc_workers_slice(btc_workers_t *pool, btc_workq_t *jobs) {
  /* Same logic as bitcoin core v0.10.0. */
  int length = pool->queue.length / (pool->threads + pool->idle + 1);

  if (length > pool->max_batch)
    length = pool->max_batch;

  if (length < 1)
    length = 1;

  btc_workq_slice(jobs, &pool->queue, length);

  return length;
}

static void
worker_thread(void *arg) {
  btc_workers_t *pool = arg;
  btc_work_t *work, *next;
  btc_workq_t jobs;
  int length = 0;

  for (;;) {
    btc_mutex_lock(&pool->mutex);

    if (length > 0) {
      pool->left -= length;

      if (!pool->stop && pool->left == 0)
        btc_cond_signal(&pool->master);
    }

    while (!pool->stop && pool->queue.length == 0) {
      pool->idle++;
      btc_cond_wait(&pool->worker, &pool->mutex);
      pool->idle--;
    }

    if (pool->stop)
      break;

    if (pool->max_batch > 1) {
      length = btc_workers_slice(pool, &jobs);

      btc_mutex_unlock(&pool->mutex);

      for (work = jobs.head; work != NULL; work = next)
        next = btc_work_execute(work);
    } else {
      work = btc_workq_shift(&pool->queue);
      length = 1;

      btc_mutex_unlock(&pool->mutex);

      btc_work_execute(work);
    }
  }

  if (--pool->threads == 0)
    btc_cond_signal(&pool->master);

  btc_mutex_unlock(&pool->mutex);
}
