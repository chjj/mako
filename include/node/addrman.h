/*!
 * addrman.h - address manager for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef BTC_ADDRMAN_H
#define BTC_ADDRMAN_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include "types.h"
#include "../satoshi/common.h"
#include "../satoshi/types.h"

/*
 * Constants
 */

/**
 * Number of days before considering
 * an address stale.
 */

#define BTC_ADDRMAN_HORIZON_DAYS 30

/**
 * Number of retries (without success)
 * before considering an address stale.
 */

#define BTC_ADDRMAN_RETRIES 3

/**
 * Number of days after reaching
 * MAX_FAILURES to consider an
 * address stale.
 */

#define BTC_ADDRMAN_MIN_FAIL_DAYS 7

/**
 * Maximum number of failures
 * allowed before considering
 * an address stale.
 */

#define BTC_ADDRMAN_MAX_FAILURES 10

/**
 * Maximum number of references
 * in fresh buckets.
 */

#define BTC_ADDRMAN_MAX_REFS 8

/**
 * Serialization version.
 */

#define BTC_ADDRMAN_VERSION 0

/**
 * Local address scores.
 */

enum btc_score {
  BTC_SCORE_NONE,
  BTC_SCORE_IF,
  BTC_SCORE_BIND,
  BTC_SCORE_DNS,
  BTC_SCORE_UPNP,
  BTC_SCORE_MANUAL,
  BTC_SCORE_MAX
};

/*
 * Address Manager
 */

BTC_EXTERN btc_addrman_t *
btc_addrman_create(const struct btc_network_s *network);

BTC_EXTERN void
btc_addrman_destroy(btc_addrman_t *man);

BTC_EXTERN void
btc_addrman_set_logger(btc_addrman_t *man, btc_logger_t *logger);

BTC_EXTERN void
btc_addrman_set_timedata(btc_addrman_t *man, const btc_timedata_t *td);

BTC_EXTERN int
btc_addrman_open(btc_addrman_t *man);

BTC_EXTERN void
btc_addrman_close(btc_addrman_t *man);

BTC_EXTERN void
btc_addrman_flush(btc_addrman_t *man);

BTC_EXTERN size_t
btc_addrman_size(btc_addrman_t *man);

BTC_EXTERN int
btc_addrman_is_full(btc_addrman_t *man);

BTC_EXTERN void
btc_addrman_reset(btc_addrman_t *man);

BTC_EXTERN void
btc_addrman_ban(btc_addrman_t *man, const btc_netaddr_t *addr);

BTC_EXTERN void
btc_addrman_unban(btc_addrman_t *man, const btc_netaddr_t *addr);

BTC_EXTERN int
btc_addrman_is_banned(btc_addrman_t *man, const btc_netaddr_t *addr);

BTC_EXTERN void
btc_addrman_clear_banned(btc_addrman_t *man);

BTC_EXTERN const btc_netaddr_t *
btc_addrman_get(btc_addrman_t *man);

BTC_EXTERN void
btc_addrman_add(btc_addrman_t *man,
                const btc_netaddr_t *addr,
                const btc_netaddr_t *src);

BTC_EXTERN void
btc_addrman_mark_attempt(btc_addrman_t *man,
                         const btc_netaddr_t *addr);

BTC_EXTERN void
btc_addrman_mark_success(btc_addrman_t *man,
                         const btc_netaddr_t *addr);

BTC_EXTERN void
btc_addrman_mark_ack(btc_addrman_t *man,
                     const btc_netaddr_t *addr,
                     int64_t services);

BTC_EXTERN void
btc_addrman_add_local(btc_addrman_t *man,
                      const btc_netaddr_t *addr,
                      enum btc_score score);

BTC_EXTERN const btc_netaddr_t *
btc_addrman_get_local(btc_addrman_t *man,
                      const btc_netaddr_t *src);

#ifdef __cplusplus
}
#endif

#endif /* BTC_ADDRMAN_H */
