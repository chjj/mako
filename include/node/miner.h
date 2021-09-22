/*!
 * miner.h - miner for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef BTC_MINER_H
#define BTC_MINER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include "types.h"
#include "../satoshi/common.h"
#include "../satoshi/types.h"

/*
 * Miner
 */

BTC_EXTERN btc_miner_t *
btc_miner_create(const struct btc_network_s *network,
                 btc_loop_t *loop,
                 btc_chain_t *chain,
                 btc_mempool_t *mempool);

BTC_EXTERN void
btc_miner_destroy(btc_miner_t *miner);

BTC_EXTERN void
btc_miner_set_logger(btc_miner_t *miner, btc_logger_t *logger);

BTC_EXTERN void
btc_miner_set_timedata(btc_miner_t *miner, const btc_timedata_t *td);

BTC_EXTERN int
btc_miner_open(btc_miner_t *miner);

BTC_EXTERN void
btc_miner_close(btc_miner_t *miner);

#ifdef __cplusplus
}
#endif

#endif /* BTC_MINER_H */
