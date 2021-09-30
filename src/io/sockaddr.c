/*!
 * sockaddr.c - socket address for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <io/core.h>

#if defined(_WIN32)
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  ifndef __MINGW32__
#    pragma comment(lib, "ws2_32.lib")
#  endif
#else
#  include <sys/types.h>
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <sys/un.h>
#endif

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
    const struct sockaddr_in *sai = (const struct sockaddr_in *)x;

    z->family = BTC_AF_INET;

    memcpy(z->raw, &sai->sin_addr, 4);

    z->port = ntohs(sai->sin_port);

    return 1;
  }

  if (x->sa_family == AF_INET6) {
    const struct sockaddr_in6 *sai = (const struct sockaddr_in6 *)x;

    z->family = BTC_AF_INET6;

    memcpy(z->raw, &sai->sin6_addr, 16);

    z->port = ntohs(sai->sin6_port);

    return 1;
  }

#ifndef _WIN32
  if (x->sa_family == AF_UNIX) {
    const struct sockaddr_un *un = (const struct sockaddr_un *)x;
    size_t len = strlen(un->sun_path);

    z->family = BTC_AF_UNIX;

    if (len + 1 > sizeof(z->path))
      return 0;

    memcpy(z->path, un->sun_path, len + 1);

    z->port = 0;

    return 1;
  }
#endif

  return 0;
}

int
btc_sockaddr_get(struct sockaddr *z, const btc_sockaddr_t *x) {
  memset(z, 0, sizeof(struct sockaddr_storage));

  if (x->family == BTC_AF_INET) {
    struct sockaddr_in *sai = (struct sockaddr_in *)z;

    sai->sin_family = AF_INET;

    memcpy(&sai->sin_addr, x->raw, 4);

    sai->sin_port = htons(x->port);

    return 1;
  }

  if (x->family == BTC_AF_INET6) {
    struct sockaddr_in6 *sai = (struct sockaddr_in6 *)z;

    sai->sin6_family = AF_INET6;

    memcpy(&sai->sin6_addr, x->raw, 16);

    sai->sin6_port = htons(x->port);

    return 1;
  }

#ifndef _WIN32
  if (x->family == BTC_AF_UNIX) {
    struct sockaddr_un *un = (struct sockaddr_un *)z;
    size_t len = strlen(x->path);

    un->sun_family = AF_UNIX;

    if (len + 1 > sizeof(un->sun_path))
      return 0;

    memcpy(un->sun_path, x->path, len + 1);

    return 1;
  }
#endif

  return 0;
}

int
btc_sockaddr_import(btc_sockaddr_t *z, const char *xp, int port) {
  btc_sockaddr_init(z);

  if (inet_pton(AF_INET, xp, (void *)z->raw) == 1) {
    z->family = BTC_AF_INET;
    z->port = port;
    return 1;
  }

  if (inet_pton(AF_INET6, xp, (void *)z->raw) == 1) {
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

    if (inet_ntop(AF_INET, (const void *)x->raw, zp, zn) == NULL)
      abort(); /* LCOV_EXCL_LINE */

    *port = x->port;

    return 1;
  }

  if (x->family == BTC_AF_INET6) {
    size_t zn = BTC_INET6_ADDRSTRLEN + 1;

    if (inet_ntop(AF_INET6, (const void *)x->raw, zp, zn) == NULL)
      abort(); /* LCOV_EXCL_LINE */

    *port = x->port;

    return 1;
  }

  *zp = '\0';
  *port = 0;

  return 0;
}
