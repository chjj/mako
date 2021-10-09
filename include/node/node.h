/*!
 * node.h - node for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef BTC_NODE_H
#define BTC_NODE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include "types.h"
#include "../satoshi/common.h"
#include "../satoshi/types.h"

/*
 * Node
 */

BTC_EXTERN btc_node_t *
btc_node_create(const btc_network_t *network);

BTC_EXTERN void
btc_node_destroy(btc_node_t *node);

BTC_EXTERN int
btc_node_open(btc_node_t *node, const char *prefix, size_t map_size);

BTC_EXTERN void
btc_node_close(btc_node_t *node);

BTC_EXTERN void
btc_node_start(btc_node_t *node);

BTC_EXTERN void
btc_node_stop(btc_node_t *node);

#ifdef __cplusplus
}
#endif

#endif /* BTC_NODE_H */
