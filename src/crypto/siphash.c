/*!
 * siphash.c - siphash for mako
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 *
 * Parts of this software are based on bitcoin/bitcoin:
 *   Copyright (c) 2009-2019, The Bitcoin Core Developers (MIT License).
 *   Copyright (c) 2009-2019, The Bitcoin Developers (MIT License).
 *   https://github.com/bitcoin/bitcoin
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/SipHash
 *   https://131002.net/siphash/
 *   https://131002.net/siphash/siphash.pdf
 *   https://github.com/bitcoin/bitcoin/blob/master/src/crypto/siphash.cpp
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <mako/crypto/siphash.h>

#include "../bio.h"
#include "../internal.h"

/*
 * Compat
 */

#undef HAVE_UMULH

#if defined(BTC_MSVC) && _MSC_VER >= 1400 /* VS 2005 */
#  include <intrin.h>
#  if defined(_M_AMD64) || defined(_M_X64) || defined(_M_ARM64)
#    pragma intrinsic(__umulh)
#    define HAVE_UMULH
#  endif
#endif

/*
 * Siphash
 */

#define SIPROUND do {                      \
  v0 += v1; v1 = ROTL64(v1, 13); v1 ^= v0; \
  v0 = ROTL64(v0, 32);                     \
  v2 += v3; v3 = ROTL64(v3, 16); v3 ^= v2; \
  v0 += v3; v3 = ROTL64(v3, 21); v3 ^= v0; \
  v2 += v1; v1 = ROTL64(v1, 17); v1 ^= v2; \
  v2 = ROTL64(v2, 32);                     \
} while (0)

uint64_t
btc_siphash_sum(const uint8_t *data, size_t size, const uint8_t *key) {
  uint64_t k0 = btc_read64le(key + 0);
  uint64_t k1 = btc_read64le(key + 8);
  uint64_t v0 = k0 ^ UINT64_C(0x736f6d6570736575);
  uint64_t v1 = k1 ^ UINT64_C(0x646f72616e646f6d);
  uint64_t v2 = k0 ^ UINT64_C(0x6c7967656e657261);
  uint64_t v3 = k1 ^ UINT64_C(0x7465646279746573);
  uint64_t f0 = (uint64_t)size << 56;
  uint64_t f1 = 0xff;
  uint64_t w;

  while (size >= 8) {
    w = btc_read64le(data);

    v3 ^= w;
    SIPROUND;
    SIPROUND;
    v0 ^= w;

    data += 8;
    size -= 8;
  }

  switch (size) {
    case 7:
      f0 |= (uint64_t)data[6] << 48;
    case 6:
      f0 |= (uint64_t)data[5] << 40;
    case 5:
      f0 |= (uint64_t)data[4] << 32;
    case 4:
      f0 |= (uint64_t)data[3] << 24;
    case 3:
      f0 |= (uint64_t)data[2] << 16;
    case 2:
      f0 |= (uint64_t)data[1] << 8;
    case 1:
      f0 |= (uint64_t)data[0];
  }

  v3 ^= f0;
  SIPROUND;
  SIPROUND;
  v0 ^= f0;
  v2 ^= f1;
  SIPROUND;
  SIPROUND;
  SIPROUND;
  SIPROUND;
  v0 ^= v1;
  v0 ^= v2;
  v0 ^= v3;

  return v0;
}

uint64_t
btc_siphash_mod(const uint8_t *data,
                size_t size,
                const uint8_t *key,
                uint64_t mod) {
  uint64_t a = btc_siphash_sum(data, size, key);
  uint64_t b = mod;

#if defined(BTC_HAVE_INT128)
  return ((btc_uint128_t)a * b) >> 64;
#elif defined(HAVE_UMULH)
  return __umulh(a, b);
#else
  /* https://stackoverflow.com/questions/28868367 */
  uint64_t ahi = a >> 32;
  uint64_t alo = a & 0xffffffff;
  uint64_t bhi = b >> 32;
  uint64_t blo = b & 0xffffffff;
  uint64_t axbhi = ahi * bhi;
  uint64_t axbmid = ahi * blo;
  uint64_t bxamid = bhi * alo;
  uint64_t axblo = alo * blo;
  uint64_t c = (axbmid & 0xffffffff) + (bxamid & 0xffffffff) + (axblo >> 32);

  return axbhi + (axbmid >> 32) + (bxamid >> 32) + (c >> 32);
#endif
}
