/*!
 * netaddr.h - network address for libsatoshi
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef BTC_NETADDR_H
#define BTC_NETADDR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "common.h"
#include "impl.h"
#include "types.h"

/*
 * Constants
 */

#define BTC_ADDRSTRLEN (65 + 8)

/*
 * Types
 */

struct btc_sockaddr_s;

/*
 * Net Address
 */

BTC_DEFINE_SERIALIZABLE_OBJECT(btc_netaddr, BTC_EXTERN)

BTC_EXTERN void
btc_netaddr_init(btc_netaddr_t *addr);

BTC_EXTERN void
btc_netaddr_clear(btc_netaddr_t *addr);

BTC_EXTERN void
btc_netaddr_copy(btc_netaddr_t *z, const btc_netaddr_t *x);

BTC_EXTERN void
btc_netaddr_set(btc_netaddr_t *addr, int family, const uint8_t *ip, int port);

BTC_EXTERN uint32_t
btc_netaddr_hash(const btc_netaddr_t *x);

BTC_EXTERN int
btc_netaddr_equal(const btc_netaddr_t *x, const btc_netaddr_t *y);

BTC_EXTERN size_t
btc_netaddr_size(const btc_netaddr_t *x);

BTC_EXTERN uint8_t *
btc_netaddr_write(uint8_t *zp, const btc_netaddr_t *x);

BTC_EXTERN int
btc_netaddr_read(btc_netaddr_t *z, const uint8_t **xp, size_t *xn);

BTC_EXTERN size_t
btc_smalladdr_size(const btc_netaddr_t *x);

BTC_EXTERN uint8_t *
btc_smalladdr_write(uint8_t *zp, const btc_netaddr_t *x);

BTC_EXTERN int
btc_smalladdr_read(btc_netaddr_t *z, const uint8_t **xp, size_t *xn);

BTC_EXTERN int
btc_netaddr_is_mapped(const btc_netaddr_t *addr);

BTC_EXTERN int
btc_netaddr_is_onion(const btc_netaddr_t *addr);

BTC_EXTERN int
btc_netaddr_is_ip4(const btc_netaddr_t *addr);

BTC_EXTERN int
btc_netaddr_is_ip6(const btc_netaddr_t *addr);

BTC_EXTERN int
btc_netaddr_is_null(const btc_netaddr_t *addr);

BTC_EXTERN int
btc_netaddr_localize(btc_netaddr_t *addr);

BTC_EXTERN int
btc_netaddr_is_broadcast(const btc_netaddr_t *addr);

BTC_EXTERN int
btc_netaddr_is_rfc1918(const btc_netaddr_t *addr);

BTC_EXTERN int
btc_netaddr_is_rfc2544(const btc_netaddr_t *addr);

BTC_EXTERN int
btc_netaddr_is_rfc3927(const btc_netaddr_t *addr);

BTC_EXTERN int
btc_netaddr_is_rfc6598(const btc_netaddr_t *addr);

BTC_EXTERN int
btc_netaddr_is_rfc5737(const btc_netaddr_t *addr);

BTC_EXTERN int
btc_netaddr_is_rfc3849(const btc_netaddr_t *addr);

BTC_EXTERN int
btc_netaddr_is_rfc3964(const btc_netaddr_t *addr);

BTC_EXTERN int
btc_netaddr_is_rfc6052(const btc_netaddr_t *addr);

BTC_EXTERN int
btc_netaddr_is_rfc4380(const btc_netaddr_t *addr);

BTC_EXTERN int
btc_netaddr_is_rfc4862(const btc_netaddr_t *addr);

BTC_EXTERN int
btc_netaddr_is_rfc4193(const btc_netaddr_t *addr);

BTC_EXTERN int
btc_netaddr_is_rfc6145(const btc_netaddr_t *addr);

BTC_EXTERN int
btc_netaddr_is_rfc4843(const btc_netaddr_t *addr);

BTC_EXTERN int
btc_netaddr_is_local(const btc_netaddr_t *addr);

BTC_EXTERN int
btc_netaddr_is_multicast(const btc_netaddr_t *addr);

BTC_EXTERN int
btc_netaddr_is_valid(const btc_netaddr_t *addr);

BTC_EXTERN int
btc_netaddr_is_routable(const btc_netaddr_t *addr);

BTC_EXTERN void
btc_netaddr_set_sockaddr(btc_netaddr_t *z, const struct btc_sockaddr_s *x);

BTC_EXTERN void
btc_netaddr_get_sockaddr(struct btc_sockaddr_s *z, const btc_netaddr_t *x);

BTC_EXTERN int
btc_netaddr_set_str(btc_netaddr_t *z, const char *xp);

BTC_EXTERN size_t
btc_netaddr_get_str(char *zp, const btc_netaddr_t *x);

#ifdef __cplusplus
}
#endif

#endif /* BTC_NETADDR_H */
