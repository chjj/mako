/*!
 * base58.c - base58 encoding for libsatoshi
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 *
 * Resources:
 *   https://github.com/bitcoin/bitcoin/blob/master/src/base58.cpp
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <satoshi/encoding.h>
#include "internal.h"

/*
 * Base58
 */

static const char *base58_charset =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static const int8_t base58_table[256] = {
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

int
btc_base58_encode(char *dst, size_t *dstlen,
                  const uint8_t *src, size_t srclen) {
  size_t zeroes = 0;
  size_t length = 0;
  size_t i, j, k, size;
  unsigned long carry;
  uint8_t *b58;

  if (srclen > 0x7fffffff)
    return 0;

  for (i = 0; i < srclen; i++) {
    if (src[i] != 0)
      break;

    zeroes += 1;
  }

  size = (uint64_t)(srclen - zeroes) * 138 / 100 + 1;
  b58 = (uint8_t *)malloc(size);

  if (b58 == NULL)
    return 0;

  memset(b58, 0, size);

  for (; i < srclen; i++) {
    carry = src[i];

    for (j = 0, k = size - 1; j < size; j++, k--) {
      if (carry == 0 && j >= length)
        break;

      carry += (unsigned long)b58[k] << 8;
      b58[k] = carry % 58;
      carry /= 58;
    }

    ASSERT(carry == 0);

    length = j;
  }

  i = size - length;

  while (i < size && b58[i] == 0)
    i += 1;

  /* Assumes sizeof(dst) >= zeroes + (size - i) + 1. */
  for (j = 0; j < zeroes; j++)
    dst[j] = '1';

  while (i < size)
    dst[j++] = base58_charset[b58[i++]];

  dst[j] = '\0';

  if (dstlen != NULL)
    *dstlen = j;

  free(b58);

  return 1;
}

int
btc_base58_decode(uint8_t *dst, size_t *dstlen,
                  const char *src, size_t srclen) {
  size_t zeroes = 0;
  size_t length = 0;
  size_t i, j, k, size;
  unsigned long carry;
  uint8_t *b256;
  uint8_t val;

#if SIZE_MAX > UINT32_MAX
  if (srclen > 0xffffffff)
    return 0;
#endif

  for (i = 0; i < srclen; i++) {
    if (src[i] != '1')
      break;

    zeroes += 1;
  }

  size = (uint64_t)srclen * 733 / 1000 + 1;
  b256 = (uint8_t *)malloc(size);

  if (b256 == NULL)
    return 0;

  memset(b256, 0, size);

  for (; i < srclen; i++) {
    val = base58_table[src[i] & 0xff];

    if (val & 0x80) {
      free(b256);
      return 0;
    }

    carry = val;

    for (j = 0, k = size - 1; j < size; j++, k--) {
      if (carry == 0 && j >= length)
        break;

      carry += (unsigned long)b256[k] * 58;
      b256[k] = carry;
      carry >>= 8;
    }

    ASSERT(carry == 0);

    length = j;
  }

  /* See: https://github.com/bitcoin/bitcoin/commit/2bcf1fc4 */
  i = size - length;

  /* Assumes sizeof(dst) >= zeroes + (size - i). */
  for (j = 0; j < zeroes; j++)
    dst[j] = 0;

  while (i < size)
    dst[j++] = b256[i++];

  if (dstlen != NULL)
    *dstlen = j;

  free(b256);

  return 1;
}

int
btc_base58_test(const char *str, size_t len) {
  while (len--) {
    if (base58_table[str[len] & 0xff] == -1)
      return 0;
  }

  return 1;
}
