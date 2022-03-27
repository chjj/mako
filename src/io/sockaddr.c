/*!
 * sockaddr.c - socket address for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <io/core.h>

#ifdef _WIN32
#  include <winsock2.h>
#  ifdef BTC_HAVE_RFC3493
#    include <ws2tcpip.h>
#  endif
#  ifndef __MINGW32__
#    pragma comment(lib, "ws2_32.lib")
#  endif
#else
#  include <sys/types.h>
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#endif

#ifndef BTC_HAVE_RFC3493
#  define sockaddr_storage sockaddr_in
#endif

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
 * Macros
 */

#define lengthof(x) (sizeof(x) / sizeof((x)[0]))

/*
 * Socket Address
 */

void
btc_sockaddr_init(btc_sockaddr_t *addr) {
  memset(addr, 0, sizeof(*addr));
  addr->family = BTC_AF_INET;
}

int
btc_sockaddr_set(btc_sockaddr_t *z, const struct sockaddr *x) {
  btc_sockaddr_init(z);

  if (x->sa_family == AF_INET) {
    const struct sockaddr_in *sai = (const struct sockaddr_in *)(void *)x;

    z->family = BTC_AF_INET;

    memcpy(z->raw, &sai->sin_addr, 4);

    z->port = ntohs(sai->sin_port);

    return 1;
  }

#ifdef BTC_HAVE_RFC3493
  if (x->sa_family == AF_INET6) {
    const struct sockaddr_in6 *sai = (const struct sockaddr_in6 *)(void *)x;

    z->family = BTC_AF_INET6;

    memcpy(z->raw, &sai->sin6_addr, 16);

    z->port = ntohs(sai->sin6_port);

    return 1;
  }
#endif

  return 0;
}

int
btc_sockaddr_get(struct sockaddr *z, const btc_sockaddr_t *x) {
  memset((void *)z, 0, sizeof(struct sockaddr_storage));

  if (x->family == BTC_AF_INET) {
    struct sockaddr_in *sai = (struct sockaddr_in *)(void *)z;

    sai->sin_family = AF_INET;

    memcpy(&sai->sin_addr, x->raw, 4);

    sai->sin_port = htons(x->port);

    return 1;
  }

#ifdef BTC_HAVE_RFC3493
  if (x->family == BTC_AF_INET6) {
    struct sockaddr_in6 *sai = (struct sockaddr_in6 *)(void *)z;

    sai->sin6_family = AF_INET6;

    memcpy(&sai->sin6_addr, x->raw, 16);

    sai->sin6_port = htons(x->port);

    return 1;
  }
#endif

  return 0;
}

int
btc_sockaddr_import(btc_sockaddr_t *z, const char *xp, int port) {
  btc_sockaddr_init(z);

  if (inet_pton4(xp, z->raw) == 0) {
    z->family = BTC_AF_INET;
    z->port = port;
    return 1;
  }

  if (inet_pton6(xp, z->raw) == 0) {
    z->family = BTC_AF_INET6;
    z->port = port;
    return 1;
  }

  btc_sockaddr_init(z);

  return 0;
}

int
btc_sockaddr_export(char *zp, int *port, const btc_sockaddr_t *x) {
  if (x->family == BTC_AF_INET) {
    size_t zn = BTC_INET_ADDRSTRLEN + 1;

    if (inet_ntop4(x->raw, zp, zn) != 0)
      abort(); /* LCOV_EXCL_LINE */

    *port = x->port;

    return 1;
  }

  if (x->family == BTC_AF_INET6) {
    size_t zn = BTC_INET6_ADDRSTRLEN + 1;

    if (inet_ntop6(x->raw, zp, zn) != 0)
      abort(); /* LCOV_EXCL_LINE */

    *port = x->port;

    return 1;
  }

  *zp = '\0';
  *port = 0;

  return 0;
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
  char tmp[BTC_INET6_ADDRSTRLEN + 1], *tp;
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
