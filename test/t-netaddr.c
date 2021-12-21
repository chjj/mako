/*!
 * t-stub.c - stub test for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <mako/netaddr.h>
#include "lib/tests.h"

const btc_netaddr_t *
decode(const char *str, btc_netaddr_t *tmp) {
  ASSERT(btc_netaddr_set_str(tmp, str));
  return tmp;
}

int main(void) {
  btc_netaddr_t addr;

  {
    static const char *vectors[] = {
      "127.0.0.1",
      "127.0.0.1:8333",
      "::1",
      "[::1]:8333",
      "192.168.1.1",
      "2001:db8:85a3::8a2e:370:7334",
      "192.168.1.1:8333",
      "[2001:db8:85a3::8a2e:370:7334]:8333"
    };

    size_t i;

    for (i = 0; i < lengthof(vectors); i++) {
      const char *xp = vectors[i];
      char yp[BTC_ADDRSTRLEN + 1];
      btc_netaddr_t x;

      ASSERT(btc_netaddr_set_str(&x, xp));
      ASSERT(btc_netaddr_get_str(yp, &x) == strlen(xp));
      ASSERT(strcmp(yp, xp) == 0);
    }
  }

#define D(str) decode(str, &addr)

  {
    static const unsigned char expect4[] = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0xff, 0xff, 0xc0, 0xa8, 0x01, 0x01
    };

    static const unsigned char expect6[] = {
      0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00,
      0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34
    };

    ASSERT(memcmp(D("192.168.1.1")->raw, expect4, 4) == 0);
    ASSERT(memcmp(D("2001:db8:85a3::8a2e:370:7334")->raw, expect6, 16) == 0);
  }

  ASSERT(btc_netaddr_is_ipv4(D("127.0.0.1")));
  ASSERT(btc_netaddr_is_ipv4(D("::FFFF:192.168.1.1")));
  ASSERT(btc_netaddr_is_ipv6(D("::1")));
  ASSERT(btc_netaddr_is_rfc1918(D("10.0.0.1")));
  ASSERT(btc_netaddr_is_rfc1918(D("192.168.1.1")));
  ASSERT(btc_netaddr_is_rfc1918(D("172.31.255.255")));
  ASSERT(btc_netaddr_is_rfc3849(D("2001:0DB8::")));
  ASSERT(btc_netaddr_is_rfc3927(D("169.254.1.1")));
  ASSERT(btc_netaddr_is_rfc3964(D("2002::1")));
  ASSERT(btc_netaddr_is_rfc4193(D("FC00::")));
  ASSERT(btc_netaddr_is_rfc4843(D("2001:10::")));
  ASSERT(btc_netaddr_is_rfc4862(D("FE80::")));
  ASSERT(btc_netaddr_is_rfc6052(D("64:FF9B::")));
  ASSERT(btc_netaddr_is_onion(D("FD87:D87E:EB43:edb1:8e4:3588:e546:35ca")));

  ASSERT(btc_netaddr_is_rfc2544(D("198.18.0.0")));
  ASSERT(btc_netaddr_is_rfc2544(D("198.19.255.255")));
  ASSERT(!btc_netaddr_is_rfc2544(D("198.17.255.255")));
  ASSERT(!btc_netaddr_is_rfc2544(D("198.20.5.255")));

  ASSERT(btc_netaddr_is_local(D("127.0.0.1")));
  ASSERT(btc_netaddr_is_local(D("::1")));
  ASSERT(btc_netaddr_is_local(D("0.1.0.0")));
  ASSERT(!btc_netaddr_is_local(D("1.0.0.0")));
  ASSERT(!btc_netaddr_is_local(D("::2")));

  ASSERT(btc_netaddr_is_rfc7343(D("2001:20::")));
  ASSERT(btc_netaddr_is_rfc7343(D("2001:2f:ffff:ffff:ffff:ffff:ffff:ffff")));
  ASSERT(!btc_netaddr_is_rfc7343(D("2002:20::")));
  ASSERT(!btc_netaddr_is_rfc7343(D("0.0.0.0")));
  ASSERT(btc_netaddr_is_rfc4380(D("2001::2")));
  ASSERT(btc_netaddr_is_rfc4380(D("2001:0:ffff:ffff:ffff:ffff:ffff:ffff")));
  ASSERT(!btc_netaddr_is_rfc4380(D("2002::")));
  ASSERT(!btc_netaddr_is_rfc4380(D("2001:1:ffff:ffff:ffff:ffff:ffff:ffff")));
  ASSERT(btc_netaddr_is_routable(D("8.8.8.8")));
  ASSERT(btc_netaddr_is_routable(D("2001::1")));
  ASSERT(btc_netaddr_is_valid(D("127.0.0.1")));

  ASSERT(btc_netaddr_network(D("127.0.0.1")) == BTC_IPNET_NONE);
  ASSERT(btc_netaddr_network(D("::1")) == BTC_IPNET_NONE);
  ASSERT(btc_netaddr_network(D("8.8.8.8")) == BTC_IPNET_IPV4);
  ASSERT(btc_netaddr_network(D("8888::8888")) == BTC_IPNET_IPV6);
  ASSERT(btc_netaddr_network(D("2001::")) == BTC_IPNET_TEREDO);
  ASSERT(btc_netaddr_network(D("FD87:D87E:EB43:edb1:8e4:3588:e546:35ca")) == BTC_IPNET_ONION);

#undef D

  return 0;
}
