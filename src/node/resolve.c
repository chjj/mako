/*!
 * resolve.c - dns resolution for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <satoshi/net.h>
#include <satoshi/netaddr.h>
#include <satoshi/network.h>
#include <satoshi/util.h>
#include <satoshi/vector.h>
#include "../internal.h"

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

/*
 * Resolve
 */

int
btc_dns_resolve(btc_vector_t *addrs,
                const char *name,
                const btc_network_t *network) {
  struct addrinfo hints, *res, *p;
  btc_netaddr_t *addr;
  int64_t now;

  memset(&hints, 0, sizeof(hints));

  hints.ai_flags = AI_V4MAPPED | AI_ADDRCONFIG;
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = 0;

  if (getaddrinfo(name, NULL, &hints, &res) != 0)
    return 0;

  now = btc_now();

  for (p = res; p != NULL; p = p->ai_next) {
    if (p->ai_family != AF_INET && p->ai_family != AF_INET6)
      continue;

    addr = btc_netaddr_create();

    CHECK(btc_netaddr_set_sockaddr(addr, p->ai_addr));

    addr->time = now;
    addr->services = BTC_NET_LOCAL_SERVICES;
    addr->port = 0;

    if (network != NULL)
      addr->port = network->port;

    btc_vector_push(addrs, addr);
  }

  freeaddrinfo(res);

  return 1;
}
