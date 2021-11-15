/*!
 * base16.c - base16 encoding for mako
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 *
 * Resources:
 *   https://tools.ietf.org/html/rfc4648
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <mako/encoding.h>
#include "internal.h"

/*
 * Base16 Engine
 */

static const char *base16_charset = "0123456789abcdef";

static const signed char base16_table[256] = {
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
   0,  1,  2,  3,  4,  5,  6,  7,
   8,  9, -1, -1, -1, -1, -1, -1,
  -1, 10, 11, 12, 13, 14, 15, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, 10, 11, 12, 13, 14, 15, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1
};

/*
 * Base16
 */

void
btc_base16_encode(char *zp, const uint8_t *xp, size_t xn) {
  while (xn--) {
    int ch = *xp++;

    *zp++ = base16_charset[ch >> 4];
    *zp++ = base16_charset[ch & 15];
  }

  *zp = '\0';
}

int
btc_base16_decode(uint8_t *zp, const char *xp, size_t xn) {
  int z = 0;

  if (xn & 1)
    return 0;

  xn >>= 1;

  while (xn--) {
    int hi = base16_table[*xp++ & 0xff];
    int lo = base16_table[*xp++ & 0xff];

    z |= hi | lo;

    *zp++ = (hi << 4) | lo;
  }

  return z >= 0;
}

int
btc_base16_test(const char *xp) {
  size_t xn = 0;

  while (*xp) {
    if (base16_table[*xp & 0xff] & 16)
      return 0;

    xp++;
    xn++;
  }

  return (xn & 1) == 0;
}

/*
 * Base16 (Little Endian)
 */

void
btc_base16le_encode(char *zp, const uint8_t *xp, size_t xn) {
  xp += xn;

  while (xn--) {
    int ch = *--xp;

    *zp++ = base16_charset[ch >> 4];
    *zp++ = base16_charset[ch & 15];
  }

  *zp = '\0';
}

int
btc_base16le_decode(uint8_t *zp, const char *xp, size_t xn) {
  int z = 0;

  if (xn & 1)
    return 0;

  xp += xn;
  xn >>= 1;

  while (xn--) {
    int lo = base16_table[*--xp & 0xff];
    int hi = base16_table[*--xp & 0xff];

    z |= hi | lo;

    *zp++ = (hi << 4) | lo;
  }

  return z >= 0;
}
