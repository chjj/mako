/*!
 * addrinfo.c - dns resolution for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stdint.h>
#include <stdlib.h>
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
#  include <netdb.h>
#  include <arpa/inet.h>
#  include <netinet/in.h>
#endif

#undef HAVE_GETIFADDRS

#if defined(__linux__)     \
 || defined(__APPLE__)     \
 || defined(__OpenBSD__)   \
 || defined(__FreeBSD__)   \
 || defined(__NetBSD__)    \
 || defined(__DragonFly__) \
 || defined(__HAIKU__)     \
 || defined(__CYGWIN__)    \
 || defined(__MSYS__)
#  include <ifaddrs.h>
#  include <net/if.h>
#  define HAVE_GETIFADDRS
#endif

/*
 * Address Info
 */

int
btc_getaddrinfo(btc_sockaddr_t **res, const char *name) {
  struct addrinfo hints, *r, *p;
  btc_sockaddr_t *addr = NULL;
  btc_sockaddr_t *prev = NULL;

  *res = NULL;

  memset(&hints, 0, sizeof(hints));

#ifdef AI_V4MAPPED
  hints.ai_flags |= AI_V4MAPPED;
#endif

#ifdef AI_ADDRCONFIG
  hints.ai_flags |= AI_ADDRCONFIG;
#endif

  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = 0;

  if (getaddrinfo(name, NULL, &hints, &r) != 0)
    return 0;

  for (p = r; p != NULL; p = p->ai_next) {
    if (p->ai_family != AF_INET && p->ai_family != AF_INET6)
      continue;

    addr = (btc_sockaddr_t *)malloc(sizeof(btc_sockaddr_t));

    if (addr == NULL)
      abort(); /* LCOV_EXCL_LINE */

    if (!btc_sockaddr_set(addr, p->ai_addr))
      abort(); /* LCOV_EXCL_LINE */

    if (*res == NULL)
      *res = addr;

    if (prev != NULL)
      prev->next = addr;

    prev = addr;
  }

  freeaddrinfo(r);

  return 1;
}

void
btc_freeaddrinfo(btc_sockaddr_t *res) {
  btc_sockaddr_t *next;

  while (res != NULL) {
    next = res->next;
    free(res);
    res = next;
  }
}

int
btc_getifaddrs(btc_sockaddr_t **res) {
#if defined(_WIN32)
  char name[256];

  *res = NULL;

  if (gethostname(name, sizeof(name)) == SOCKET_ERROR)
    return 0;

  return btc_getaddrinfo(res, name);
#elif defined(HAVE_GETIFADDRS)
  btc_sockaddr_t *addr = NULL;
  btc_sockaddr_t *prev = NULL;
  struct ifaddrs *r, *p;

  *res = NULL;

  if (getifaddrs(&r) != 0)
    return 0;

  for (p = r; p != NULL; p = p->ifa_next) {
    if (p->ifa_addr == NULL)
      continue;

    if ((p->ifa_flags & IFF_UP) == 0)
      continue;

    if (strcmp(p->ifa_name, "lo") == 0)
      continue;

    if (strcmp(p->ifa_name, "lo0") == 0)
      continue;

    if (p->ifa_addr->sa_family != AF_INET
        && p->ifa_addr->sa_family != AF_INET6) {
      continue;
    }

    addr = (btc_sockaddr_t *)malloc(sizeof(btc_sockaddr_t));

    if (addr == NULL)
      abort(); /* LCOV_EXCL_LINE */

    if (!btc_sockaddr_set(addr, p->ifa_addr))
      abort(); /* LCOV_EXCL_LINE */

    if (*res == NULL)
      *res = addr;

    if (prev != NULL)
      prev->next = addr;

    prev = addr;
  }

  freeifaddrs(r);

  return 1;
#else /* !HAVE_GETIFADDRS */
  *res = NULL;
  return 0;
#endif /* !HAVE_GETIFADDRS */
}

void
btc_freeifaddrs(btc_sockaddr_t *res) {
  btc_freeaddrinfo(res);
}
