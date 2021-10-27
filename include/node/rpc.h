/*!
 * rpc.h - rpc for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef BTC_RPC_H
#define BTC_RPC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include "types.h"
#include "../satoshi/common.h"
#include "../satoshi/types.h"

/*
 * RPC
 */

BTC_EXTERN btc_rpc_t *
btc_rpc_create(btc_node_t *node);

BTC_EXTERN void
btc_rpc_destroy(btc_rpc_t *rpc);

BTC_EXTERN int
btc_rpc_open(btc_rpc_t *rpc);

BTC_EXTERN void
btc_rpc_close(btc_rpc_t *rpc);

struct _json_value;

BTC_EXTERN struct _json_value *
btc_rpc_call(btc_rpc_t *rpc,
             const char *method,
             const struct _json_value *params);

#ifdef __cplusplus
}
#endif

#endif /* BTC_RPC_H */
