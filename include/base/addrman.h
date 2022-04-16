/*!
 * addrman.h - address manager for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifndef BTC_ADDRMAN_H
#define BTC_ADDRMAN_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "types.h"
#include "../mako/common.h"
#include "../mako/types.h"

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
 * Types
 */

typedef struct btc_addrent_s {
  btc_netaddr_t addr;
  btc_netaddr_t src;
  uint8_t used;
  int32_t ref_count;
  int32_t attempts;
  int64_t last_success;
  int64_t last_attempt;
  size_t rand_pos;
  struct btc_addrent_s *prev;
  struct btc_addrent_s *next;
} btc_addrent_t;

/*
 * Address Manager
 */

BTC_EXTERN btc_addrman_t *
btc_addrman_create(const btc_network_t *network);

BTC_EXTERN void
btc_addrman_destroy(btc_addrman_t *man);

BTC_EXTERN void
btc_addrman_set_logger(btc_addrman_t *man, btc_logger_t *logger);

BTC_EXTERN void
btc_addrman_set_timedata(btc_addrman_t *man, const btc_timedata_t *td);

BTC_EXTERN void
btc_addrman_set_proxy(btc_addrman_t *man, const btc_netaddr_t *addr);

BTC_EXTERN void
btc_addrman_set_bantime(btc_addrman_t *man, int64_t ban_time);

BTC_EXTERN int
btc_addrman_open(btc_addrman_t *man, const char *file, unsigned int flags);

BTC_EXTERN void
btc_addrman_close(btc_addrman_t *man);

BTC_EXTERN void
btc_addrman_flush(btc_addrman_t *man);

BTC_EXTERN size_t
btc_addrman_total(btc_addrman_t *man);

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

BTC_EXTERN const btc_addrent_t *
btc_addrman_get(btc_addrman_t *man);

BTC_EXTERN int
btc_addrman_add(btc_addrman_t *man,
                const btc_netaddr_t *addr,
                const btc_netaddr_t *src);

BTC_EXTERN int
btc_addrman_remove(btc_addrman_t *man, const btc_netaddr_t *addr);

BTC_EXTERN void
btc_addrman_mark_attempt(btc_addrman_t *man,
                         const btc_netaddr_t *addr);

BTC_EXTERN void
btc_addrman_mark_success(btc_addrman_t *man,
                         const btc_netaddr_t *addr);

BTC_EXTERN void
btc_addrman_mark_ack(btc_addrman_t *man,
                     const btc_netaddr_t *addr,
                     uint64_t services);

BTC_EXTERN int
btc_addrman_has_local(btc_addrman_t *man,
                      const btc_netaddr_t *addr);

BTC_EXTERN const btc_netaddr_t *
btc_addrman_get_local(btc_addrman_t *man,
                      const btc_netaddr_t *dst,
                      uint64_t services);

BTC_EXTERN int
btc_addrman_add_local(btc_addrman_t *man,
                      const btc_netaddr_t *addr,
                      int score);

BTC_EXTERN int
btc_addrman_mark_local(btc_addrman_t *man,
                       const btc_netaddr_t *addr);

BTC_EXTERN const btc_netmap_t *
btc_addrman_map(const btc_addrman_t *man);

BTC_EXTERN btc_vector_t *
btc_addrman_getaddr(btc_addrman_t *man);

BTC_EXTERN size_t
btc_addrman_size(const btc_addrman_t *man);

BTC_EXTERN size_t
btc_addrman_export(uint8_t *zp, const btc_addrman_t *man);

BTC_EXTERN int
btc_addrman_import(btc_addrman_t *man, const uint8_t *xp, size_t xn);

#ifdef __cplusplus
}
#endif

#endif /* BTC_ADDRMAN_H */
