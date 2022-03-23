/*!
 * netaddr.c - network address for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <mako/netaddr.h>
#include <mako/util.h>
#include "impl.h"
#include "internal.h"

/*
 * Constants
 */

static const uint8_t btc_ipv4_mapped[12] = {
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0xff, 0xff
};

static const uint8_t btc_local_ip[16] = {
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x01
};

static const uint8_t btc_zero_ip[16] = {
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00
};

static const uint8_t btc_rfc6052[12] = {
  0x00, 0x64, 0xff, 0x9b,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00
};

static const uint8_t btc_rfc4862[8] = {
  0xfe, 0x80, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00
};

static const uint8_t btc_rfc6145[12] = {
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0xff, 0xff, 0x00, 0x00
};

static const uint8_t btc_shifted[9] = {
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0xff,
  0xff
};

static const uint8_t btc_tor_onion[6] = {
  0xfd, 0x87, 0xd8, 0x7e,
  0xeb, 0x43
};

enum btc_reachability {
  BTC_REACH_UNREACHABLE,
  BTC_REACH_DEFAULT,
  BTC_REACH_TEREDO,
  BTC_REACH_IPV6_WEAK,
  BTC_REACH_IPV4,
  BTC_REACH_IPV6_STRONG,
  BTC_REACH_PRIVATE
};

/*
 * Types
 */

/* Must match <io/core.h> exactly. */
typedef struct btc_sockaddr_s {
  int family;
  uint8_t raw[32];
  int port;
  struct btc_sockaddr_s *next;
} btc_sockaddr_t;

#define BTC_AF_UNSPEC 0
#define BTC_AF_INET 4
#define BTC_AF_INET6 6

/*
 * Helpers
 */

static int
inet_pton4(const char *src, unsigned char *dst);

static int
inet_pton6(const char *src, unsigned char *dst);

static int
inet_ntop4(const unsigned char *src, char *dst, size_t size);

static int
inet_ntop6(const unsigned char *src, char *dst, size_t size);

/*
 * Net Address
 */

DEFINE_SERIALIZABLE_OBJECT(btc_netaddr, SCOPE_EXTERN)

void
btc_netaddr_init(btc_netaddr_t *addr) {
  memset(addr, 0, sizeof(*addr));
}

void
btc_netaddr_clear(btc_netaddr_t *addr) {
  (void)addr;
}

void
btc_netaddr_copy(btc_netaddr_t *z, const btc_netaddr_t *x) {
  *z = *x;
}

int
btc_netaddr_set(btc_netaddr_t *z, const char *addr, int port) {
  btc_netaddr_init(z);

  if (inet_pton4(addr, z->raw + 12) == 0) {
    memset(z->raw +  0, 0x00, 10);
    memset(z->raw + 10, 0xff, 2);
    z->port = port;
    return 1;
  }

  if (inet_pton6(addr, z->raw) == 0) {
    z->port = port;
    return 1;
  }

  return 0;
}

void
btc_netaddr_get(char *zp, const btc_netaddr_t *x) {
  if (btc_netaddr_is_mapped(x))
    CHECK(inet_ntop4(x->raw + 12, zp, BTC_ADDRSTRLEN + 1) == 0);
  else
    CHECK(inet_ntop6(x->raw, zp, BTC_ADDRSTRLEN + 1) == 0);
}

uint32_t
btc_netaddr_hash(const btc_netaddr_t *x) {
  return btc_murmur3_sum(x->raw, 16, (uint32_t)x->port ^ 0xfba4c795);
}

int
btc_netaddr_equal(const btc_netaddr_t *x, const btc_netaddr_t *y) {
  if (x->port != y->port)
    return 0;

  return memcmp(x->raw, y->raw, 16) == 0;
}

size_t
btc_netaddr_size(const btc_netaddr_t *x) {
  (void)x;
  return 4 + 8 + 16 + 2;
}

uint8_t *
btc_netaddr_write(uint8_t *zp, const btc_netaddr_t *x) {
  zp = btc_time_write(zp, x->time);
  zp = btc_uint64_write(zp, x->services);
  zp = btc_raw_write(zp, x->raw, 16);
  *zp++ = (x->port >> 8) & 0xff;
  *zp++ = (x->port >> 0) & 0xff;
  return zp;
}

int
btc_netaddr_read(btc_netaddr_t *z, const uint8_t **xp, size_t *xn) {
  if (!btc_time_read(&z->time, xp, xn))
    return 0;

  if (!btc_uint64_read(&z->services, xp, xn))
    return 0;

  if (!btc_raw_read(z->raw, 16, xp, xn))
    return 0;

  if (*xn < 2)
    return 0;

  z->port = ((int)(*xp)[0] << 8) | ((*xp)[1] << 0);

  *xp += 2;
  *xn -= 2;

  return 1;
}

size_t
btc_smalladdr_size(const btc_netaddr_t *x) {
  (void)x;
  return 8 + 16 + 2;
}

uint8_t *
btc_smalladdr_write(uint8_t *zp, const btc_netaddr_t *x) {
  zp = btc_uint64_write(zp, x->services);
  zp = btc_raw_write(zp, x->raw, 16);
  *zp++ = (x->port >> 8) & 0xff;
  *zp++ = (x->port >> 0) & 0xff;
  return zp;
}

int
btc_smalladdr_read(btc_netaddr_t *z, const uint8_t **xp, size_t *xn) {
  if (!btc_uint64_read(&z->services, xp, xn))
    return 0;

  if (!btc_raw_read(z->raw, 16, xp, xn))
    return 0;

  if (*xn < 2)
    return 0;

  z->port = ((int)(*xp)[0] << 8) | ((*xp)[1] << 0);

  *xp += 2;
  *xn -= 2;

  return 1;
}

int
btc_netaddr_is_mapped(const btc_netaddr_t *addr) {
  return btc_memcmp(addr->raw, btc_ipv4_mapped, sizeof(btc_ipv4_mapped)) == 0;
}

int
btc_netaddr_is_onion(const btc_netaddr_t *addr) {
  return btc_memcmp(addr->raw, btc_tor_onion, sizeof(btc_tor_onion)) == 0;
}

int
btc_netaddr_is_ipv4(const btc_netaddr_t *addr) {
  return btc_netaddr_is_mapped(addr);
}

int
btc_netaddr_is_ipv6(const btc_netaddr_t *addr) {
  return !btc_netaddr_is_mapped(addr) && !btc_netaddr_is_onion(addr);
}

int
btc_netaddr_is_null(const btc_netaddr_t *addr) {
  if (btc_netaddr_is_ipv4(addr)) {
    /* 0.0.0.0 */
    return addr->raw[12] == 0
        && addr->raw[13] == 0
        && addr->raw[14] == 0
        && addr->raw[15] == 0;
  }

  /* :: */
  return btc_memcmp(addr->raw, btc_zero_ip, 16) == 0;
}

int
btc_netaddr_localize(btc_netaddr_t *addr) {
  if (btc_netaddr_is_null(addr)) {
    if (btc_netaddr_is_ipv4(addr)) {
      addr->raw[12] = 127;
      addr->raw[15] = 1;
    } else {
      addr->raw[15] = 1;
    }
  }

  return 1;
}

int
btc_netaddr_is_broadcast(const btc_netaddr_t *addr) {
  if (!btc_netaddr_is_ipv4(addr))
    return 0;

  /* 255.255.255.255 */
  return addr->raw[12] == 255
      && addr->raw[13] == 255
      && addr->raw[14] == 255
      && addr->raw[15] == 255;
}

int
btc_netaddr_is_rfc1918(const btc_netaddr_t *addr) {
  if (!btc_netaddr_is_ipv4(addr))
    return 0;

  if (addr->raw[12] == 10)
    return 1;

  if (addr->raw[12] == 192 && addr->raw[13] == 168)
    return 1;

  if (addr->raw[12] == 172 && (addr->raw[13] >= 16 && addr->raw[13] <= 31))
    return 1;

  return 0;
}

int
btc_netaddr_is_rfc2544(const btc_netaddr_t *addr) {
  if (!btc_netaddr_is_ipv4(addr))
    return 0;

  if (addr->raw[12] == 198 && (addr->raw[13] == 18 || addr->raw[13] == 19))
    return 1;

  return 0;
}

int
btc_netaddr_is_rfc3927(const btc_netaddr_t *addr) {
  if (!btc_netaddr_is_ipv4(addr))
    return 0;

  if (addr->raw[12] == 169 && addr->raw[13] == 254)
    return 1;

  return 0;
}

int
btc_netaddr_is_rfc6598(const btc_netaddr_t *addr) {
  if (!btc_netaddr_is_ipv4(addr))
    return 0;

  if (addr->raw[12] == 100
      && (addr->raw[13] >= 64 && addr->raw[13] <= 127)) {
    return 1;
  }

  return 0;
}

int
btc_netaddr_is_rfc5737(const btc_netaddr_t *addr) {
  if (!btc_netaddr_is_ipv4(addr))
    return 0;

  if (addr->raw[12] == 192
      && (addr->raw[13] == 0 && addr->raw[14] == 2)) {
    return 1;
  }

  if (addr->raw[12] == 198 && addr->raw[13] == 51 && addr->raw[14] == 100)
    return 1;

  if (addr->raw[12] == 203 && addr->raw[13] == 0 && addr->raw[14] == 113)
    return 1;

  return 0;
}

int
btc_netaddr_is_rfc3849(const btc_netaddr_t *addr) {
  if (addr->raw[0] == 0x20 && addr->raw[1] == 0x01
      && addr->raw[2] == 0x0d && addr->raw[3] == 0xb8) {
    return 1;
  }

  return 0;
}

int
btc_netaddr_is_rfc3964(const btc_netaddr_t *addr) {
  if (addr->raw[0] == 0x20 && addr->raw[1] == 0x02)
    return 1;

  return 0;
}

int
btc_netaddr_is_rfc6052(const btc_netaddr_t *addr) {
  return btc_memcmp(addr->raw, btc_rfc6052, sizeof(btc_rfc6052)) == 0;
}

int
btc_netaddr_is_rfc4380(const btc_netaddr_t *addr) {
  if (addr->raw[0] == 0x20 && addr->raw[1] == 0x01
      && addr->raw[2] == 0x00 && addr->raw[3] == 0x00) {
    return 1;
  }

  return 0;
}

int
btc_netaddr_is_rfc4862(const btc_netaddr_t *addr) {
  return btc_memcmp(addr->raw, btc_rfc4862, sizeof(btc_rfc4862)) == 0;
}

int
btc_netaddr_is_rfc4193(const btc_netaddr_t *addr) {
  if ((addr->raw[0] & 0xfe) == 0xfc)
    return 1;

  return 0;
}

int
btc_netaddr_is_rfc6145(const btc_netaddr_t *addr) {
  return btc_memcmp(addr->raw, btc_rfc6145, sizeof(btc_rfc6145)) == 0;
}

int
btc_netaddr_is_rfc4843(const btc_netaddr_t *addr) {
  if (addr->raw[0] == 0x20 && addr->raw[1] == 0x01
      && addr->raw[2] == 0x00 && (addr->raw[3] & 0xf0) == 0x10) {
    return 1;
  }

  return 0;
}

int
btc_netaddr_is_rfc7343(const btc_netaddr_t *addr) {
  if (addr->raw[0] == 0x20 && addr->raw[1] == 0x01
      && addr->raw[2] == 0x00 && (addr->raw[3] & 0xf0) == 0x20) {
    return 1;
  }

  return 0;
}

int
btc_netaddr_is_local(const btc_netaddr_t *addr) {
  if (btc_netaddr_is_ipv4(addr)) {
    if (addr->raw[12] == 127 || addr->raw[12] == 0)
      return 1;
    return 0;
  }

  if (btc_memcmp(addr->raw, btc_local_ip, sizeof(btc_local_ip)) == 0)
    return 1;

  return 0;
}

int
btc_netaddr_is_multicast(const btc_netaddr_t *addr) {
  if (btc_netaddr_is_ipv4(addr)) {
    if ((addr->raw[12] & 0xf0) == 0xe0)
      return 1;
    return 0;
  }

  return addr->raw[0] == 0xff;
}

int
btc_netaddr_is_valid(const btc_netaddr_t *addr) {
  if (btc_memcmp(addr->raw, btc_shifted, sizeof(btc_shifted)) == 0)
    return 0;

  if (btc_netaddr_is_null(addr))
    return 0;

  if (btc_netaddr_is_broadcast(addr))
    return 0;

  if (btc_netaddr_is_rfc3849(addr))
    return 0;

  return 1;
}

int
btc_netaddr_is_routable(const btc_netaddr_t *addr) {
  if (!btc_netaddr_is_valid(addr))
    return 0;

  if (btc_netaddr_is_rfc1918(addr))
    return 0;

  if (btc_netaddr_is_rfc2544(addr))
    return 0;

  if (btc_netaddr_is_rfc3927(addr))
    return 0;

  if (btc_netaddr_is_rfc4862(addr))
    return 0;

  if (btc_netaddr_is_rfc6598(addr))
    return 0;

  if (btc_netaddr_is_rfc5737(addr))
    return 0;

  if (btc_netaddr_is_rfc4193(addr) && !btc_netaddr_is_onion(addr))
    return 0;

  if (btc_netaddr_is_rfc4843(addr))
    return 0;

  if (btc_netaddr_is_rfc7343(addr))
    return 0;

  if (btc_netaddr_is_local(addr))
    return 0;

  return 1;
}

enum btc_ipnet
btc_netaddr_network(const btc_netaddr_t *addr) {
  if (!btc_netaddr_is_routable(addr))
    return BTC_IPNET_NONE;

  if (btc_netaddr_is_ipv4(addr))
    return BTC_IPNET_IPV4;

  if (btc_netaddr_is_rfc4380(addr))
    return BTC_IPNET_TEREDO;

  if (btc_netaddr_is_onion(addr))
    return BTC_IPNET_ONION;

  return BTC_IPNET_IPV6;
}

int
btc_netaddr_reachability(const btc_netaddr_t *src, const btc_netaddr_t *dst) {
  enum btc_ipnet srcnet, dstnet;

  if (!btc_netaddr_is_routable(src))
    return BTC_REACH_UNREACHABLE;

  srcnet = btc_netaddr_network(src);
  dstnet = btc_netaddr_network(dst);

  switch (dstnet) {
    case BTC_IPNET_IPV4:
      switch (srcnet) {
        case BTC_IPNET_IPV4:
          return BTC_REACH_IPV4;
        default:
          return BTC_REACH_DEFAULT;
      }
      break;
    case BTC_IPNET_IPV6:
      switch (srcnet) {
        case BTC_IPNET_TEREDO:
          return BTC_REACH_TEREDO;
        case BTC_IPNET_IPV4:
          return BTC_REACH_IPV4;
        case BTC_IPNET_IPV6:
          if (btc_netaddr_is_rfc3964(src)
              || btc_netaddr_is_rfc6052(src)
              || btc_netaddr_is_rfc6145(src)) {
            /* tunnel */
            return BTC_REACH_IPV6_WEAK;
          }
          return BTC_REACH_IPV6_STRONG;
        default:
          return BTC_REACH_DEFAULT;
      }
      break;
    case BTC_IPNET_ONION:
      switch (srcnet) {
        case BTC_IPNET_IPV4:
          return BTC_REACH_IPV4;
        case BTC_IPNET_ONION:
          return BTC_REACH_PRIVATE;
        default:
          return BTC_REACH_DEFAULT;
      }
      break;
    case BTC_IPNET_TEREDO:
      switch (srcnet) {
        case BTC_IPNET_TEREDO:
          return BTC_REACH_TEREDO;
        case BTC_IPNET_IPV6:
          return BTC_REACH_IPV6_WEAK;
        case BTC_IPNET_IPV4:
          return BTC_REACH_IPV4;
        default:
          return BTC_REACH_DEFAULT;
      }
      break;
    default:
      switch (srcnet) {
        case BTC_IPNET_TEREDO:
          return BTC_REACH_TEREDO;
        case BTC_IPNET_IPV6:
          return BTC_REACH_IPV6_WEAK;
        case BTC_IPNET_IPV4:
          return BTC_REACH_IPV4;
        case BTC_IPNET_ONION:
          return BTC_REACH_PRIVATE;
        default:
          return BTC_REACH_DEFAULT;
      }
      break;
  }

  return BTC_REACH_UNREACHABLE;
}

uint8_t *
btc_netaddr_groupkey(uint8_t *out, const btc_netaddr_t *addr) {
  /* See: https://github.com/bitcoin/bitcoin/blob/e258ce7/src/netaddress.cpp#L413 */
  /* Todo: Use IP->ASN mapping, see:
     https://github.com/bitcoin/bitcoin/blob/adea5e1/src/addrman.h#L274 */
  int type = 6; /* NET_IPV6 */
  int start = 0;
  int bits = 16;
  int i = 0;

  memset(out, 0, 6);

  if (btc_netaddr_is_local(addr)) {
    type = 255; /* NET_LOCAL */
    bits = 0;
  } else if (!btc_netaddr_is_routable(addr)) {
    type = 0; /* NET_UNROUTABLE */
    bits = 0;
  } else if (btc_netaddr_is_ipv4(addr)
          || btc_netaddr_is_ipv6(addr)
          || btc_netaddr_is_rfc6052(addr)) {
    type = 4; /* NET_IPV4 */
    start = 12;
  } else if (btc_netaddr_is_rfc3964(addr)) {
    type = 4; /* NET_IPV4 */
    start = 2;
  } else if (btc_netaddr_is_rfc4380(addr)) {
    out[0] = 4; /* NET_IPV4 */
    out[1] = addr->raw[12] ^ 0xff;
    out[2] = addr->raw[13] ^ 0xff;
    return out;
  } else if (btc_netaddr_is_onion(addr)) {
    type = 8; /* NET_ONION */
    start = 6;
    bits = 4;
  } else if (addr->raw[0] == 0x20
          && addr->raw[1] == 0x01
          && addr->raw[2] == 0x04
          && addr->raw[3] == 0x70) {
    bits = 36;
  } else {
    bits = 32;
  }

  out[i++] = type;

  while (bits >= 8) {
    out[i++] = addr->raw[start++];
    bits -= 8;
  }

  if (bits > 0)
    out[i++] = addr->raw[start] | ((1 << (8 - bits)) - 1);

  return out;
}

void
btc_netaddr_set_sockaddr(btc_netaddr_t *z, const btc_sockaddr_t *x) {
  btc_netaddr_init(z);

  if (x->family == BTC_AF_INET) {
    memset(z->raw +  0, 0x00, 10);
    memset(z->raw + 10, 0xff, 2);
    memcpy(z->raw + 12, x->raw, 4);
  } else if (x->family == BTC_AF_INET6) {
    memcpy(z->raw, x->raw, 16);
  } else {
    btc_abort(); /* LCOV_EXCL_LINE */
  }

  z->port = x->port;
}

void
btc_netaddr_get_sockaddr(btc_sockaddr_t *z, const btc_netaddr_t *x) {
  memset(z, 0, sizeof(*z));

  if (btc_netaddr_is_mapped(x)) {
    z->family = BTC_AF_INET;
    memcpy(z->raw, x->raw + 12, 4);
  } else {
    z->family = BTC_AF_INET6;
    memcpy(z->raw, x->raw, 16);
  }

  z->port = x->port;
}

int
btc_netaddr_set_str(btc_netaddr_t *z, const char *xp) {
  char tmp[BTC_ADDRSTRLEN + 1];
  const char *pp = NULL;
  const char *tp = xp;
  int port = 0;
  int len = 0;
  int sq = -1;
  int co = -1;
  int col = 0;
  int family;

  btc_netaddr_init(z);

  while (*tp) {
    int ch = *tp++;

    if (ch == ']')
      sq = len;

    if (ch == ':') {
      co = len;
      col += 1;
    }

    if (++len > BTC_ADDRSTRLEN)
      return 0;
  }

  if (xp[0] == '[') {
    if (sq == -1)
      return 0;

    if (col < 2)
      return 0;

    xp++;
    sq--;

    memcpy(tmp, xp, sq);

    tmp[sq] = '\0';

    if (xp[sq + 1] != '\0') {
      if (xp[sq + 1] != ':')
        return 0;

      pp = xp + sq + 2;
    }

    family = 6;
  } else if (col > 1) {
    memcpy(tmp, xp, len + 1);

    family = 6;
  } else if (co != -1) {
    pp = xp + co + 1;

    memcpy(tmp, xp, co);

    tmp[co] = '\0';

    family = 4;
  } else {
    memcpy(tmp, xp, len + 1);

    family = 4;
  }

  if (pp != NULL) {
    len = 0;

    while (*pp) {
      int ch = *pp++;

      if (ch < '0' || ch > '9')
        return 0;

      if (len > 0 && port == 0)
        return 0;

      port *= 10;
      port += (ch - '0');

      len += 1;

      if (len > 5 || port > 0xffff)
        return 0;
    }

    if (len == 0)
      return 0;
  }

  if (family == 4) {
    memset(z->raw +  0, 0x00, 10);
    memset(z->raw + 10, 0xff, 2);

    if (inet_pton4(tmp, z->raw + 12) != 0)
      return 0;
  } else {
    if (inet_pton6(tmp, z->raw) != 0)
      return 0;
  }

  z->port = port;

  return 1;
}

size_t
btc_netaddr_get_str(char *zp, const btc_netaddr_t *x) {
  char tmp[BTC_ADDRSTRLEN + 1];
  int c;

  if (btc_netaddr_is_mapped(x)) {
    CHECK(inet_ntop4(x->raw + 12, tmp, sizeof(tmp) - 6) == 0);

    if (x->port != 0) {
      c = sprintf(zp, "%s:%d", tmp, x->port);
    } else {
      c = strlen(tmp);
      memcpy(zp, tmp, c + 1);
    }
  } else {
    CHECK(inet_ntop6(x->raw, tmp, sizeof(tmp) - 8) == 0);

    if (x->port != 0) {
      c = sprintf(zp, "[%s]:%d", tmp, x->port);
    } else {
      c = strlen(tmp);
      memcpy(zp, tmp, c + 1);
    }
  }

  CHECK(c >= 0);

  return c;
}

/**
 * Portable inet_{pton,ntop}.
 *
 * Code from libuv[1]. According to c-ares[2][3], this code was
 * written in 1996 by Paul Vixie and is under the ISC license.
 *
 * See LICENSE for more information.
 *
 * [1] https://github.com/libuv/libuv/blob/385b796/src/inet.c
 * [2] https://github.com/c-ares/c-ares/blob/c2f3235/src/lib/inet_ntop.c
 * [3] https://github.com/c-ares/c-ares/blob/c2f3235/src/lib/inet_net_pton.c
 */

static int
inet_pton4(const char *src, unsigned char *dst) {
  static const char digits[] = "0123456789";
  int saw_digit, octets, ch;
  unsigned char tmp[4], *tp;

  saw_digit = 0;
  octets = 0;

  *(tp = tmp) = 0;

  while ((ch = *src++) != '\0') {
    const char *pch;

    if ((pch = strchr(digits, ch)) != NULL) {
      unsigned int nw = *tp * 10 + (pch - digits);

      if (saw_digit && *tp == 0)
        return -1;

      if (nw > 255)
        return -1;

      *tp = nw;

      if (!saw_digit) {
        if (++octets > 4)
          return -1;

        saw_digit = 1;
      }
    } else if (ch == '.' && saw_digit) {
      if (octets == 4)
        return -1;

      *++tp = 0;
      saw_digit = 0;
    } else {
      return -1;
    }
  }

  if (octets < 4)
    return -1;

  memcpy(dst, tmp, 4);

  return 0;
}

static int
inet_pton6(const char *src, unsigned char *dst) {
  static const char xdigits_l[] = "0123456789abcdef",
                    xdigits_u[] = "0123456789ABCDEF";
  unsigned char tmp[16], *tp, *endp, *colonp;
  const char *xdigits, *curtok;
  int ch, seen_xdigits;
  unsigned int val;

  memset((tp = tmp), 0, sizeof(tmp));

  endp = tp + sizeof(tmp);
  colonp = NULL;

  /* Leading :: requires some special handling. */
  if (*src == ':') {
    if (*++src != ':')
      return -1;
  }

  curtok = src;
  seen_xdigits = 0;
  val = 0;

  while ((ch = *src++) != '\0') {
    const char *pch;

    if ((pch = strchr((xdigits = xdigits_l), ch)) == NULL)
      pch = strchr((xdigits = xdigits_u), ch);

    if (pch != NULL) {
      val <<= 4;
      val |= (pch - xdigits);

      if (++seen_xdigits > 4)
        return -1;

      continue;
    }

    if (ch == ':') {
      curtok = src;

      if (!seen_xdigits) {
        if (colonp)
          return -1;

        colonp = tp;

        continue;
      } else if (*src == '\0') {
        return -1;
      }

      if (tp + 2 > endp)
        return -1;

      *tp++ = (unsigned char)(val >> 8) & 0xff;
      *tp++ = (unsigned char)val & 0xff;

      seen_xdigits = 0;
      val = 0;

      continue;
    }

    if (ch == '.' && ((tp + 4) <= endp)) {
      int err = inet_pton4(curtok, tp);

      if (err == 0) {
        tp += 4;
        seen_xdigits = 0;
        break;  /*%< '\\0' was seen by inet_pton4(). */
      }
    }

    return -1;
  }

  if (seen_xdigits) {
    if (tp + 2 > endp)
      return -1;

    *tp++ = (unsigned char)(val >> 8) & 0xff;
    *tp++ = (unsigned char)val & 0xff;
  }

  if (colonp != NULL) {
    /*
     * Since some memmove()'s erroneously fail to handle
     * overlapping regions, we'll do the shift by hand.
     */
    int n = tp - colonp;
    int i;

    if (tp == endp)
      return -1;

    for (i = 1; i <= n; i++) {
      endp[-i] = colonp[n - i];
      colonp[n - i] = 0;
    }

    tp = endp;
  }

  if (tp != endp)
    return -1;

  memcpy(dst, tmp, sizeof(tmp));

  return 0;
}

static int
inet_ntop4(const unsigned char *src, char *dst, size_t size) {
  static const char fmt[] = "%u.%u.%u.%u";
  char tmp[4 * 10 + 3 + 1];
  int c;

  c = sprintf(tmp, fmt, src[0], src[1], src[2], src[3]);

  if (c <= 0 || (size_t)c + 1 > size)
    return -1;

  memcpy(dst, tmp, c + 1);

  return 0;
}

static int
inet_ntop6(const unsigned char *src, char *dst, size_t size) {
  /*
   * Note that int32_t and int16_t need only be "at least" large enough
   * to contain a value of the specified size.  On some systems, like
   * Crays, there is no such thing as an integer variable with 16 bits.
   * Keep this in mind if you think this function should have been coded
   * to use pointer overlays.  All the world's not a VAX.
   */
  struct { int base, len; } best, cur;
  char tmp[BTC_ADDRSTRLEN + 1], *tp;
  unsigned int words[16 / 2];
  int i;

  /*
   * Preprocess:
   *  Copy the input (bytewise) array into a wordwise array.
   *  Find the longest run of 0x00's in src[] for :: shorthanding.
   */
  memset(words, 0, sizeof(words));

  for (i = 0; i < 16; i++)
    words[i / 2] |= (src[i] << ((1 - (i % 2)) << 3));

  best.base = -1;
  best.len = 0;
  cur.base = -1;
  cur.len = 0;

  for (i = 0; i < (int)lengthof(words); i++) {
    if (words[i] == 0) {
      if (cur.base == -1) {
        cur.base = i;
        cur.len = 1;
      } else {
        cur.len++;
      }
    } else {
      if (cur.base != -1) {
        if (best.base == -1 || cur.len > best.len)
          best = cur;

        cur.base = -1;
      }
    }
  }

  if (cur.base != -1) {
    if (best.base == -1 || cur.len > best.len)
      best = cur;
  }

  if (best.base != -1 && best.len < 2)
    best.base = -1;

  /*
   * Format the result.
   */
  tp = tmp;

  for (i = 0; i < (int)lengthof(words); i++) {
    /* Are we inside the best run of 0x00's? */
    if (best.base != -1 && i >= best.base && i < (best.base + best.len)) {
      if (i == best.base)
        *tp++ = ':';

      continue;
    }

    /* Are we following an initial run of 0x00s or any real hex? */
    if (i != 0)
      *tp++ = ':';

    /* Is this address an encapsulated IPv4? */
    if (i == 6 && best.base == 0 && (best.len == 6
        || (best.len == 7 && words[7] != 0x0001)
        || (best.len == 5 && words[5] == 0xffff))) {
      int err = inet_ntop4(src + 12, tp, sizeof(tmp) - (tp - tmp));

      if (err)
        return err;

      tp += strlen(tp);

      break;
    }

    tp += sprintf(tp, "%x", words[i]);
  }

  /* Was it a trailing run of 0x00's? */
  if (best.base != -1 && (best.base + best.len) == lengthof(words))
    *tp++ = ':';

  *tp++ = '\0';

  if ((size_t)(tp - tmp) > size)
    return -1;

  memcpy(dst, tmp, tp - tmp);

  return 0;
}
