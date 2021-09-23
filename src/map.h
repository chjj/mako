/*!
 * map.h - map for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef BTC_MAP_H
#define BTC_MAP_H

#include <stdint.h>
#include <string.h>
#include <satoshi/types.h>
#include <satoshi/util.h>
#include "internal.h"

#define kh_inline BTC_INLINE
#define kh_unused BTC_UNUSED

#include "khash.h"

#define kh_hash_hash_func(x) btc_murmur3_sum(x, 32, 0xfba4c795)
#define kh_hash_hash_equal(x, y) (memcmp(x, y, 32) == 0)

#define KHASH_SET_INIT_HASH(name)                          \
  KHASH_INIT(name, uint8_t *, char, 0, kh_hash_hash_func,  \
                                       kh_hash_hash_equal)

#define KHASH_MAP_INIT_HASH(name, khval_t)                    \
  KHASH_INIT(name, uint8_t *, khval_t, 1, kh_hash_hash_func,  \
                                          kh_hash_hash_equal)

#define KHASH_SET_INIT_CONST_HASH(name)                          \
  KHASH_INIT(name, const uint8_t *, char, 0, kh_hash_hash_func,  \
                                             kh_hash_hash_equal)

#define KHASH_MAP_INIT_CONST_HASH(name, khval_t)                    \
  KHASH_INIT(name, const uint8_t *, khval_t, 1, kh_hash_hash_func,  \
                                                kh_hash_hash_equal)

#define KHASH_SET_INIT_OUTPOINT(name)                             \
  KHASH_INIT(name, btc_outpoint_t *, char, 0, btc_outpoint_hash,  \
                                              btc_outpoint_equal)

#define KHASH_MAP_INIT_OUTPOINT(name, khval_t)                       \
  KHASH_INIT(name, btc_outpoint_t *, khval_t, 1, btc_outpoint_hash,  \
                                                 btc_outpoint_equal)

#define KHASH_SET_INIT_CONST_OUTPOINT(name)                             \
  KHASH_INIT(name, const btc_outpoint_t *, char, 0, btc_outpoint_hash,  \
                                                    btc_outpoint_equal)

#define KHASH_MAP_INIT_CONST_OUTPOINT(name, khval_t)                       \
  KHASH_INIT(name, const btc_outpoint_t *, khval_t, 1, btc_outpoint_hash,  \
                                                       btc_outpoint_equal)

#define KHASH_SET_INIT_NETADDR(name)                            \
  KHASH_INIT(name, btc_netaddr_t *, char, 0, btc_netaddr_hash,  \
                                             btc_netaddr_equal)

#define KHASH_MAP_INIT_NETADDR(name, khval_t)                      \
  KHASH_INIT(name, btc_netaddr_t *, khval_t, 1, btc_netaddr_hash,  \
                                                btc_netaddr_equal)

#define KHASH_SET_INIT_CONST_NETADDR(name)                            \
  KHASH_INIT(name, const btc_netaddr_t *, char, 0, btc_netaddr_hash,  \
                                                   btc_netaddr_equal)

#define KHASH_MAP_INIT_CONST_NETADDR(name, khval_t)                      \
  KHASH_INIT(name, const btc_netaddr_t *, khval_t, 1, btc_netaddr_hash,  \
                                                      btc_netaddr_equal)

#endif /* BTC_MAP_H */
