/*!
 * resolve.h - dns resolution for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef BTC_RESOLVE_H
#define BTC_RESOLVE_H

#include <satoshi/types.h>

/*
 * Resolve
 */

int
btc_dns_resolve(btc_vector_t *addrs,
                const char *name,
                const struct btc_network_s *network);

#endif /* BTC_RESOLVE_H */
