/*!
 * workers.h - thread pool for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifndef BTC_WORKERS_H
#define BTC_WORKERS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "../mako/common.h"

/*
 * Types
 */

typedef void btc_work_f(void *arg);

typedef struct btc_work_s {
  btc_work_f *func;
  void *arg;
  struct btc_work_s *next;
} btc_work_t;

typedef struct btc_workq_s {
  btc_work_t *head;
  btc_work_t *tail;
  int length;
} btc_workq_t;

typedef struct btc_workers_s btc_workers_t;

/*
 * Work Queue
 */

BTC_EXTERN void
btc_workq_init(btc_workq_t *queue);

BTC_EXTERN void
btc_workq_clear(btc_workq_t *queue);

BTC_EXTERN void
btc_workq_push(btc_workq_t *queue, btc_work_f *func, void *arg);

/*
 * Workers
 */

BTC_EXTERN btc_workers_t *
btc_workers_create(int threads, int max_batch);

BTC_EXTERN void
btc_workers_destroy(btc_workers_t *pool);

BTC_EXTERN void
btc_workers_add(btc_workers_t *pool, btc_work_f *func, void *arg);

BTC_EXTERN void
btc_workers_batch(btc_workers_t *pool, btc_workq_t *batch);

BTC_EXTERN void
btc_workers_wait(btc_workers_t *pool);

#ifdef __cplusplus
}
#endif

#endif /* BTC_WORKERS_H */
