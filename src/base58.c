/*!
 * base58.c - base58 encoding for mako
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 *
 * Resources:
 *   https://github.com/bitcoin/bitcoin/blob/master/src/base58.cpp
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <mako/encoding.h>
#include <mako/util.h>
#include "internal.h"

/*
 * Base58
 */

static const char *base58_charset =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static const signed char base58_table[256] = {
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1,  0,  1,  2,  3,  4,  5,  6,
   7,  8, -1, -1, -1, -1, -1, -1,
  -1,  9, 10, 11, 12, 13, 14, 15,
  16, -1, 17, 18, 19, 20, 21, -1,
  22, 23, 24, 25, 26, 27, 28, 29,
  30, 31, 32, -1, -1, -1, -1, -1,
  -1, 33, 34, 35, 36, 37, 38, 39,
  40, 41, 42, 43, -1, 44, 45, 46,
  47, 48, 49, 50, 51, 52, 53, 54,
  55, 56, 57, -1, -1, -1, -1, -1,
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

void
btc_base58_encode(char *zp, const uint8_t *xp, size_t xn) {
  uint8_t b58[(512 * 138) / 100 + 1]; /* 707 */
  int i, j, k, size, carry;
  int zeroes = 0;
  int length = 0;

  if (xn > 512)
    abort(); /* LCOV_EXCL_LINE */

  for (i = 0; i < (int)xn; i++) {
    if (xp[i] != 0)
      break;

    zeroes += 1;
  }

  size = ((xn - zeroes) * 138) / 100 + 1;

  memset(b58, 0, size);

  for (; i < (int)xn; i++) {
    carry = xp[i];

    for (j = 0, k = size - 1; j < size; j++, k--) {
      if (carry == 0 && j >= length)
        break;

      carry += (int)b58[k] << 8;
      b58[k] = carry % 58;
      carry /= 58;
    }

    ASSERT(carry == 0);

    length = j;
  }

  i = size - length;

  while (i < size && b58[i] == 0)
    i += 1;

  /* Assumes sizeof(zp) >= zeroes + (size - i) + 1. */
  for (j = 0; j < zeroes; j++)
    zp[j] = '1';

  while (i < size)
    zp[j++] = base58_charset[b58[i++]];

  zp[j] = '\0';

  btc_memzero(b58, size);
}

int
btc_base58_decode(uint8_t *zp, size_t *zn, const char *xp, size_t xn) {
  uint8_t b256[(1024 * 733) / 1000 + 1]; /* 751 */
  int i, j, k, size, val, carry;
  int zeroes = 0;
  int length = 0;

  if (xn > 1024)
    return 0;

  for (i = 0; i < (int)xn; i++) {
    if (xp[i] != '1')
      break;

    zeroes += 1;
  }

  size = (xn * 733) / 1000 + 1;

  memset(b256, 0, size);

  for (; i < (int)xn; i++) {
    val = base58_table[xp[i] & 0xff];

    if (val == -1) {
      btc_memzero(b256, size);
      return 0;
    }

    carry = val;

    for (j = 0, k = size - 1; j < size; j++, k--) {
      if (carry == 0 && j >= length)
        break;

      carry += (int)b256[k] * 58;
      b256[k] = carry;
      carry >>= 8;
    }

    ASSERT(carry == 0);

    length = j;
  }

  /* See: https://github.com/bitcoin/bitcoin/commit/2bcf1fc4 */
  i = size - length;

  /* Assumes sizeof(zp) >= zeroes + (size - i). */
  for (j = 0; j < zeroes; j++)
    zp[j] = 0;

  while (i < size)
    zp[j++] = b256[i++];

  if (zn != NULL)
    *zn = j;

  btc_memzero(b256, size);

  return 1;
}

int
btc_base58_test(const char *xp) {
  while (*xp) {
    if (base58_table[*xp & 0xff] == -1)
      return 0;

    xp++;
  }

  return 1;
}
