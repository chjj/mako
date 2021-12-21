/*!
 * rpc.h - rpc for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifndef BTC_RPC_H
#define BTC_RPC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include "types.h"
#include "../mako/common.h"
#include "../mako/types.h"

/*
 * RPC
 */

BTC_EXTERN btc_rpc_t *
btc_rpc_create(btc_node_t *node);

BTC_EXTERN void
btc_rpc_destroy(btc_rpc_t *rpc);

BTC_EXTERN void
btc_rpc_set_port(btc_rpc_t *rpc, int port);

BTC_EXTERN void
btc_rpc_set_bind(btc_rpc_t *rpc, const btc_netaddr_t *addr);

BTC_EXTERN void
btc_rpc_set_credentials(btc_rpc_t *rpc, const char *user, const char *pass);

BTC_EXTERN int
btc_rpc_open(btc_rpc_t *rpc, unsigned int flags);

BTC_EXTERN void
btc_rpc_close(btc_rpc_t *rpc);

BTC_EXTERN btc_json_t *
btc_rpc_call(btc_rpc_t *rpc, const char *method, const btc_json_t *params);

#ifdef __cplusplus
}
#endif

#endif /* BTC_RPC_H */
