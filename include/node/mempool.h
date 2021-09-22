/*!
 * mempool.h - mempool for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef BTC_MEMPOOL_H
#define BTC_MEMPOOL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include "types.h"
#include "../satoshi/common.h"
#include "../satoshi/types.h"

BTC_EXTERN btc_mempool_t *
btc_mempool_create(const struct btc_network_s *network, btc_chain_t *chain);

BTC_EXTERN void
btc_mempool_destroy(btc_mempool_t *mp);

BTC_EXTERN void
btc_mempool_set_logger(btc_mempool_t *mp, btc_logger_t *logger);

BTC_EXTERN void
btc_mempool_set_timedata(btc_mempool_t *mp, const btc_timedata_t *td);

BTC_EXTERN int
btc_mempool_open(btc_mempool_t *mp);

BTC_EXTERN void
btc_mempool_close(btc_mempool_t *mp);

#ifdef __cplusplus
}
#endif

#endif /* BTC_MEMPOOL_H */
