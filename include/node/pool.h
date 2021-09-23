/*!
 * pool.h - p2p pool for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef BTC_POOL_H
#define BTC_POOL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include "types.h"
#include "../satoshi/common.h"
#include "../satoshi/types.h"

BTC_EXTERN btc_pool_t *
btc_pool_create(const struct btc_network_s *network,
                btc_loop_t *loop,
                btc_chain_t *chain,
                btc_mempool_t *mempool);

BTC_EXTERN void
btc_pool_destroy(btc_pool_t *pool);

BTC_EXTERN void
btc_pool_set_logger(btc_pool_t *pool, btc_logger_t *logger);

BTC_EXTERN void
btc_pool_set_timedata(btc_pool_t *pool, btc_timedata_t *td);

BTC_EXTERN int
btc_pool_open(btc_pool_t *pool);

BTC_EXTERN void
btc_pool_close(btc_pool_t *pool);

#ifdef __cplusplus
}
#endif

#endif /* BTC_POOL_H */
