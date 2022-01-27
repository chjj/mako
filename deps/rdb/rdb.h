/*!
 * rdb.h - database for mako
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifndef RDB_H
#define RDB_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

/*
 * Flags
 */

#define RDB_RDONLY (0 << 0)
#define RDB_RDWR (1 << 1)
#define RDB_CREATE (1 << 2)
#define RDB_NOTHREADS (1 << 30) /* internal */

/*
 * Errors
 */

#define RDB_OK 0
#define RDB_EINVAL -1
#define RDB_ENOTFOUND -2
#define RDB_ECORRUPTION -3
#define RDB_ENOUPDATE -4
#define RDB_EBADWRITE -5
#define RDB_EBADOPEN -6
#define RDB_EBADCLOSE -7

/*
 * Types
 */

typedef struct rdb_s rdb_t;
typedef struct rdb_txn_s rdb_txn_t;
typedef struct rdb_iter_s rdb_iter_t;

/*
 * Database
 */

rdb_t *
rdb_create(void);

void
rdb_destroy(rdb_t *db);

int
rdb_open(rdb_t *db, const char *file, unsigned int flags, unsigned int mode);

int
rdb_close(rdb_t *db);

int
rdb_compact(rdb_t *db);

int
rdb_fd(rdb_t *db);

int
rdb_sync(rdb_t *db);

/*
 * Transaction
 */

rdb_txn_t *
rdb_txn_create(rdb_t *db);

void
rdb_txn_destroy(rdb_txn_t *tx);

void
rdb_txn_reset(rdb_txn_t *tx);

int
rdb_txn_get(rdb_txn_t *tx,
            const unsigned char **value,
            size_t *size,
            const unsigned char *key,
            size_t length);

int
rdb_txn_has(rdb_txn_t *tx, const unsigned char *key, size_t length);

int
rdb_txn_put(rdb_txn_t *tx,
            const unsigned char *key,
            size_t length,
            const unsigned char *value,
            size_t size);

int
rdb_txn_del(rdb_txn_t *tx, const unsigned char *key, size_t length);

int
rdb_txn_commit(rdb_txn_t *tx);

/*
 * Iterator
 */

rdb_iter_t *
rdb_iter_create(rdb_txn_t *tx);

void
rdb_iter_destroy(rdb_iter_t *iter);

int
rdb_iter_first(rdb_iter_t *iter);

int
rdb_iter_seek(rdb_iter_t *iter, const unsigned char *key, size_t length);

int
rdb_iter_next(rdb_iter_t *iter);

int
rdb_iter_key(rdb_iter_t *iter, const unsigned char **key, size_t *length);

int
rdb_iter_value(rdb_iter_t *iter, const unsigned char **value, size_t *size);

/*
 * Helpers
 */

const char *
rdb_strerror(int code);

size_t
rdb_memusage(void);

#ifdef __cplusplus
}
#endif

#endif /* RDB_H */
