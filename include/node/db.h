/*!
 * db.h - leveldb wrapper for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef BTC_DB_H
#define BTC_DB_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include "satoshi/common.h"

/*
 * Types
 */

typedef struct btc_db_s btc_db_t;
typedef struct btc_batch_s btc_batch_t;
typedef struct btc_iter_s btc_iter_t;

/*
 * Database
 */

BTC_EXTERN btc_db_t *
btc_db_create(void);

BTC_EXTERN int
btc_db_open(btc_db_t *db, const char *path, size_t map_size);

BTC_EXTERN void
btc_db_close(btc_db_t *db);

BTC_EXTERN void
btc_db_destroy(btc_db_t *db);

BTC_EXTERN int
btc_db_has(btc_db_t *db, const unsigned char *key, size_t klen);

BTC_EXTERN int
btc_db_get(btc_db_t *db, unsigned char **val, size_t *vlen,
                         const unsigned char *key, size_t klen);

BTC_EXTERN int
btc_db_put(btc_db_t *db, const unsigned char *key, size_t klen,
                         const unsigned char *val, size_t vlen);

BTC_EXTERN int
btc_db_del(btc_db_t *db, const unsigned char *key, size_t klen);

BTC_EXTERN int
btc_db_write(btc_db_t *db, btc_batch_t *bat);

/*
 * Batch
 */

BTC_EXTERN btc_batch_t *
btc_batch_create(btc_db_t *db);

BTC_EXTERN void
btc_batch_destroy(btc_batch_t *bat);

BTC_EXTERN void
btc_batch_put(btc_batch_t *bat, const unsigned char *key, size_t klen,
                                const unsigned char *val, size_t vlen);

BTC_EXTERN void
btc_batch_del(btc_batch_t *bat, const unsigned char *key, size_t klen);

/*
 * Iterator
 */

BTC_EXTERN btc_iter_t *
btc_iter_create(btc_db_t *db, int use_snapshot);

BTC_EXTERN void
btc_iter_destroy(btc_iter_t *iter);

BTC_EXTERN int
btc_iter_valid(const btc_iter_t *iter);

BTC_EXTERN void
btc_iter_seek_first(btc_iter_t *iter);

BTC_EXTERN void
btc_iter_seek_last(btc_iter_t *iter);

BTC_EXTERN void
btc_iter_seek(btc_iter_t *iter, const unsigned char *key, size_t klen);

BTC_EXTERN void
btc_iter_next(btc_iter_t *iter);

BTC_EXTERN void
btc_iter_prev(btc_iter_t *iter);

BTC_EXTERN const unsigned char *
btc_iter_key(const btc_iter_t *iter, size_t *klen);

BTC_EXTERN const unsigned char *
btc_iter_val(const btc_iter_t *iter, size_t *vlen);

BTC_EXTERN int
btc_iter_check(const btc_iter_t *iter);

/*
 * Util
 */

BTC_EXTERN void
btc_db_free(void *ptr);

#ifdef __cplusplus
}
#endif

#endif /* BTC_DB_H */
