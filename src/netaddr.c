/*!
 * netaddr.c - network address for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <satoshi/netaddr.h>
#include <satoshi/util.h>
#include "impl.h"
#include "internal.h"

#if defined(_WIN32)
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  ifndef __MINGW32__
#    pragma comment(lib, "ws2_32.lib")
#  endif
#else
#  include <sys/types.h>
#  include <sys/socket.h>
#  include <arpa/inet.h>
#endif

/*
 * Constants
 */

static const uint8_t btc_ip4_mapped[12] = {
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

/*
 * Net Address
 */

DEFINE_SERIALIZABLE_OBJECT(btc_netaddr, SCOPE_EXTERN)

void
btc_netaddr_init(btc_netaddr_t *addr) {
  addr->time = 0;
  addr->services = 0;
  memset(addr->raw, 0, sizeof(addr->raw));
  addr->port = 0;
}

void
btc_netaddr_clear(btc_netaddr_t *addr) {
  (void)addr;
}

void
btc_netaddr_copy(btc_netaddr_t *z, const btc_netaddr_t *x) {
  *z = *x;
}

void
btc_netaddr_set(btc_netaddr_t *addr, int family, const uint8_t *ip, int port) {
  CHECK(family == 4 || family == 6);

  if (family == 4) {
    memset(addr->raw +  0, 0x00, 10);
    memset(addr->raw + 10, 0xff, 2);
    memcpy(addr->raw + 12, ip, 4);
  } else {
    memcpy(addr->raw, ip, 16);
  }

  addr->port = port & 0xffff;
}

uint32_t
btc_netaddr_hash(const btc_netaddr_t *x) {
  uint8_t tmp[18];

  btc_raw_write(tmp, x->raw, 16);
  btc_uint32_write(tmp + 16, x->port);

  return btc_murmur3_sum(tmp, 18, 0xfba4c795);
}

int
btc_netaddr_equal(const btc_netaddr_t *x, const btc_netaddr_t *y) {
  if (memcmp(x->raw, y->raw, 36) != 0)
    return 0;

  if (x->port != y->port)
    return 0;

  return 1;
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
  return btc_memcmp(addr->raw, btc_ip4_mapped, sizeof(btc_ip4_mapped)) == 0;
}

int
btc_netaddr_is_onion(const btc_netaddr_t *addr) {
  return btc_memcmp(addr->raw, btc_tor_onion, sizeof(btc_tor_onion)) == 0;
}

int
btc_netaddr_is_ip4(const btc_netaddr_t *addr) {
  return btc_netaddr_is_mapped(addr);
}

int
btc_netaddr_is_ip6(const btc_netaddr_t *addr) {
  return !btc_netaddr_is_mapped(addr) && !btc_netaddr_is_onion(addr);
}

int
btc_netaddr_is_null(const btc_netaddr_t *addr) {
  if (btc_netaddr_is_ip4(addr)) {
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
    if (btc_netaddr_is_ip4(addr)) {
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
  if (!btc_netaddr_is_ip4(addr))
    return 0;

  /* 255.255.255.255 */
  return addr->raw[12] == 255
      && addr->raw[13] == 255
      && addr->raw[14] == 255
      && addr->raw[15] == 255;
}

int
btc_netaddr_is_rfc1918(const btc_netaddr_t *addr) {
  if (!btc_netaddr_is_ip4(addr))
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
  if (!btc_netaddr_is_ip4(addr))
    return 0;

  if (addr->raw[12] == 198 && (addr->raw[13] == 18 || addr->raw[13] == 19))
    return 1;

  if (addr->raw[12] == 169 && addr->raw[13] == 254)
    return 1;

  return 0;
}

int
btc_netaddr_is_rfc3927(const btc_netaddr_t *addr) {
  if (!btc_netaddr_is_ip4(addr))
    return 0;

  if (addr->raw[12] == 169 && addr->raw[13] == 254)
    return 1;

  return 0;
}

int
btc_netaddr_is_rfc6598(const btc_netaddr_t *addr) {
  if (!btc_netaddr_is_ip4(addr))
    return 0;

  if (addr->raw[12] == 100
      && (addr->raw[13] >= 64 && addr->raw[13] <= 127)) {
    return 1;
  }

  return 0;
}

int
btc_netaddr_is_rfc5737(const btc_netaddr_t *addr) {
  if (!btc_netaddr_is_ip4(addr))
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
btc_netaddr_is_local(const btc_netaddr_t *addr) {
  if (btc_netaddr_is_ip4(addr)) {
    if (addr->raw[12] == 127 && addr->raw[13] == 0)
      return 1;
    return 0;
  }

  if (btc_memcmp(addr->raw, btc_local_ip, sizeof(btc_local_ip)) == 0)
    return 1;

  return 0;
}

int
btc_netaddr_is_multicast(const btc_netaddr_t *addr) {
  if (btc_netaddr_is_ip4(addr)) {
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

  if (btc_netaddr_is_local(addr))
    return 0;

  return 1;
}

int
btc_netaddr_set_sockaddr(btc_netaddr_t *z, const struct sockaddr *x) {
  btc_netaddr_init(z);

  if (x->sa_family == PF_INET) {
    const struct sockaddr_in *sai = (const struct sockaddr_in *)x;

    btc_netaddr_set(z, 4, (const uint8_t *)&sai->sin_addr, 0);

    z->port = ntohs(sai->sin_port);

    return 1;
  }

  if (x->sa_family == PF_INET6) {
    const struct sockaddr_in6 *sai = (const struct sockaddr_in6 *)x;

    btc_netaddr_set(z, 6, (const uint8_t *)&sai->sin6_addr, 0);

    z->port = ntohs(sai->sin6_port);

    return 1;
  }

  return 0;
}

void
btc_netaddr_get_sockaddr(struct sockaddr *z, const btc_netaddr_t *x) {
  memset(z, 0, sizeof(struct sockaddr_storage));

  if (btc_netaddr_is_mapped(x)) {
    struct sockaddr_in *sai = (struct sockaddr_in *)z;

    sai->sin_family = PF_INET;

    memcpy(&sai->sin_addr, x->raw + 12, 4);

    sai->sin_port = htons(x->port);
  } else {
    struct sockaddr_in6 *sai = (struct sockaddr_in6 *)z;

    sai->sin6_family = PF_INET6;

    memcpy(&sai->sin6_addr, x->raw, 16);

    sai->sin6_port = htons(x->port);
  }
}

int
btc_netaddr_set_str(btc_netaddr_t *z, const char *xp) {
  struct sockaddr_storage storage;
  struct sockaddr *sa = (struct sockaddr *)&storage;
  char str[INET6_ADDRSTRLEN + 1];
  const char *pstr = NULL;
  size_t len = strlen(xp);
  int family = PF_INET;
  int port = 0;

  if (len > INET6_ADDRSTRLEN)
    return 0;

  if (strchr(xp, '.') != NULL) {
    const char *ch = strchr(xp, ':');

    if (ch != NULL) {
      pstr = ch + 1;

      memcpy(str, xp, ch - xp);

      str[ch - xp] = '\0';
    } else {
      memcpy(str, xp, len + 1);
    }

    family = PF_INET;
  } else if (xp[0] == '[') {
    const char *ch = strchr(xp, ']');

    if (ch == NULL)
      return 0;

    xp++;

    memcpy(str, xp, ch - xp);

    str[ch - xp] = '\0';

    if (ch[1] != '\0') {
      if (ch[1] != ':')
        return 0;

      pstr = ch + 2;
    }

    family = PF_INET6;
  } else {
    memcpy(str, xp, len + 1);

    family = PF_INET6;
  }

  if (pstr != NULL) {
    while (*pstr) {
      int ch = *pstr++;

      if (ch < '0' || ch > '9')
        return 0;

      port *= 10;
      port += (ch - '0');

      if (port > 0xffff)
        return 0;
    }
  }

  memset(sa, 0, sizeof(storage));

  if (family == PF_INET) {
    struct sockaddr_in *sai = (struct sockaddr_in *)sa;

    if (inet_pton(AF_INET, str, &sai->sin_addr) != 1)
      return 0;

    sai->sin_family = PF_INET;
    sai->sin_port = htons(port);
  } else {
    struct sockaddr_in6 *sai = (struct sockaddr_in6 *)sa;

    if (inet_pton(AF_INET6, str, &sai->sin6_addr) != 1)
      return 0;

    sai->sin6_family = PF_INET6;
    sai->sin6_port = htons(port);
  }

  return btc_netaddr_set_sockaddr(z, sa);
}

void
btc_netaddr_get_str(char *zp, const btc_netaddr_t *x) {
  struct sockaddr_storage storage;
  struct sockaddr *sa = (struct sockaddr *)&storage;

  btc_netaddr_get_sockaddr(sa, x);

  if (sa->sa_family == PF_INET) {
    struct sockaddr_in *sai = (struct sockaddr_in *)sa;
    size_t size = sizeof(struct in_addr);
    char str[INET_ADDRSTRLEN + 1];

    CHECK(inet_ntop(AF_INET, &sai->sin_addr, str, size) != NULL);

    if (x->port != 0)
      sprintf(zp, "%s:%d", str, x->port);
    else
      strcpy(zp, str);
  } else {
    struct sockaddr_in6 *sai = (struct sockaddr_in6 *)sa;
    size_t size = sizeof(struct in6_addr);
    char str[INET6_ADDRSTRLEN + 1];

    CHECK(inet_ntop(AF_INET6, &sai->sin6_addr, str, size) != NULL);

    if (x->port != 0)
      sprintf(zp, "[%s]:%d", str, x->port);
    else
      strcpy(zp, str);
  }
}
