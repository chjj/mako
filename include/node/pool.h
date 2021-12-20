/*!
 * pool.h - p2p pool for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifndef BTC_POOL_H
#define BTC_POOL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include "types.h"
#include "../mako/common.h"
#include "../mako/types.h"

BTC_EXTERN btc_pool_t *
btc_pool_create(const btc_network_t *network,
                struct btc_loop_s *loop,
                btc_chain_t *chain,
                btc_mempool_t *mempool);

BTC_EXTERN void
btc_pool_destroy(btc_pool_t *pool);

BTC_EXTERN void
btc_pool_set_logger(btc_pool_t *pool, btc_logger_t *logger);

BTC_EXTERN void
btc_pool_set_timedata(btc_pool_t *pool, btc_timedata_t *td);

BTC_EXTERN void
btc_pool_set_port(btc_pool_t *pool, int port);

BTC_EXTERN void
btc_pool_set_bind(btc_pool_t *pool, const btc_netaddr_t *addr);

BTC_EXTERN void
btc_pool_set_external(btc_pool_t *pool, const btc_netaddr_t *addr);

BTC_EXTERN void
btc_pool_set_connect(btc_pool_t *pool, const btc_netaddr_t *addr);

BTC_EXTERN void
btc_pool_set_proxy(btc_pool_t *pool, const btc_netaddr_t *addr);

BTC_EXTERN void
btc_pool_set_maxinbound(btc_pool_t *pool, size_t max_inbound);

BTC_EXTERN void
btc_pool_set_maxoutbound(btc_pool_t *pool, size_t max_outbound);

BTC_EXTERN void
btc_pool_set_bantime(btc_pool_t *pool, int64_t ban_time);

BTC_EXTERN void
btc_pool_set_onlynet(btc_pool_t *pool, enum btc_ipnet only_net);

BTC_EXTERN int
btc_pool_open(btc_pool_t *pool, const char *prefix, unsigned int flags);

BTC_EXTERN void
btc_pool_close(btc_pool_t *pool);

BTC_EXTERN void
btc_pool_announce_block(btc_pool_t *pool,
                        const btc_block_t *block,
                        const uint8_t *hash);

BTC_EXTERN void
btc_pool_announce_tx(btc_pool_t *pool, const btc_mpentry_t *entry);

BTC_EXTERN void
btc_pool_handle_badorphan(btc_pool_t *pool,
                          const char *msg,
                          const btc_verify_error_t *err,
                          unsigned int id);

#ifdef __cplusplus
}
#endif

#endif /* BTC_POOL_H */
