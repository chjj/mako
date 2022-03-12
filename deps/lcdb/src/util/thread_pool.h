/*!
 * thread_pool.h - thread pool for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 */

#ifndef LDB_THREAD_POOL_H
#define LDB_THREAD_POOL_H

/*
 * Types
 */

typedef void ldb_work_f(void *arg);
typedef struct ldb_pool_s ldb_pool_t;

/*
 * Workers
 */

ldb_pool_t *
ldb_pool_create(int threads);

void
ldb_pool_destroy(ldb_pool_t *pool);

void
ldb_pool_schedule(ldb_pool_t *pool, ldb_work_f *func, void *arg);

void
ldb_pool_wait(ldb_pool_t *pool);

#endif /* LDB_THREAD_POOL_H */
