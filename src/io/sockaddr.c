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
#  include <arpa/inet.h>
#endif

/*
 * Socket Address
 */

void
btc_sockaddr_init(btc_sockaddr_t *addr) {
  addr->family = 4;
  memset(addr->raw, 0, sizeof(addr->raw));
  addr->port = 0;
  addr->next = NULL;
}

int
btc_sockaddr_set(btc_sockaddr_t *z, const struct sockaddr *x) {
  btc_sockaddr_init(z);

  if (x->sa_family == PF_INET) {
    const struct sockaddr_in *sai = (const struct sockaddr_in *)x;

    z->family = 4;

    memcpy(z->raw, (const uint8_t *)&sai->sin_addr, 4);

    z->port = ntohs(sai->sin_port);

    return 1;
  }

  if (x->sa_family == PF_INET6) {
    const struct sockaddr_in6 *sai = (const struct sockaddr_in6 *)x;

    z->family = 6;

    memcpy(z->raw, (const uint8_t *)&sai->sin6_addr, 16);

    z->port = ntohs(sai->sin6_port);

    return 1;
  }

  return 0;
}

void
btc_sockaddr_get(struct sockaddr *z, const btc_sockaddr_t *x) {
  memset(z, 0, sizeof(struct sockaddr_storage));

  if (x->family == 4) {
    struct sockaddr_in *sai = (struct sockaddr_in *)z;

    sai->sin_family = PF_INET;

    memcpy(&sai->sin_addr, x->raw, 4);

    sai->sin_port = htons(x->port);
  } else {
    struct sockaddr_in6 *sai = (struct sockaddr_in6 *)z;

    sai->sin6_family = PF_INET6;

    memcpy(&sai->sin6_addr, x->raw, 16);

    sai->sin6_port = htons(x->port);
  }
}

int
btc_sockaddr_import(btc_sockaddr_t *z, const char *xp, int port) {
  struct sockaddr_storage storage;
  struct sockaddr *sa = (struct sockaddr *)&storage;
  struct sockaddr_in *sai4 = (struct sockaddr_in *)sa;
  struct sockaddr_in6 *sai6 = (struct sockaddr_in6 *)sa;

  memset(sa, 0, sizeof(storage));

  if (inet_pton(AF_INET, xp, &sai4->sin_addr) == 1) {
    sai4->sin_family = PF_INET;
    sai4->sin_port = htons(port);
  } else if (inet_pton(AF_INET6, xp, &sai6->sin6_addr) == 1) {
    sai6->sin6_family = PF_INET6;
    sai6->sin6_port = htons(port);
  } else {
    return 0;
  }

  return btc_sockaddr_set(z, sa);
}

void
btc_sockaddr_export(char *zp, int *port, const btc_sockaddr_t *x) {
  struct sockaddr_storage storage;
  struct sockaddr *sa = (struct sockaddr *)&storage;

  btc_sockaddr_get(sa, x);

  if (sa->sa_family == PF_INET) {
    struct sockaddr_in *sai = (struct sockaddr_in *)sa;
    size_t zn = BTC_INET_ADDRSTRLEN + 1;

    if (inet_ntop(AF_INET, &sai->sin_addr, zp, zn) == NULL)
      abort(); /* LCOV_EXCL_LINE */

    *port = ntohs(sai->sin_port);
  } else {
    struct sockaddr_in6 *sai = (struct sockaddr_in6 *)sa;
    size_t zn = BTC_INET6_ADDRSTRLEN + 1;

    if (inet_ntop(AF_INET6, &sai->sin6_addr, zp, zn) == NULL)
      abort(); /* LCOV_EXCL_LINE */

    *port = ntohs(sai->sin6_port);
  }
}
