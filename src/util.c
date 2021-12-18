/*!
 * util.c - utils for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
#  include <windows.h> /* SecureZeroMemory */
#endif
#include <mako/encoding.h>
#include <mako/util.h>
#include "internal.h"

/*
 * Memory Zero
 */

void
btc_memzero(void *ptr, size_t len) {
#if defined(_WIN32) && defined(SecureZeroMemory)
  if (len > 0)
    SecureZeroMemory(ptr, len);
#elif defined(BTC_HAVE_ASM)
  if (len > 0) {
    memset(ptr, 0, len);

    __asm__ __volatile__ (
      ""
      :: "r" (ptr)
      : "memory"
    );
  }
#else
  static void *(*volatile memset_ptr)(void *, int, size_t) = memset;

  if (len > 0)
    memset_ptr(ptr, 0, len);
#endif
}

/*
 * Memory Compare
 */

int
btc_memcmp(const void *x, const void *y, size_t n) {
  /* Exposing this function is necessary to avoid a
   * particularly nasty GCC bug[1][2].
   *
   * [1] https://gcc.gnu.org/bugzilla/show_bug.cgi?id=95189
   * [2] https://github.com/bitcoin-core/secp256k1/issues/823
   */
  const unsigned char *xp = (const unsigned char *)x;
  const unsigned char *yp = (const unsigned char *)y;
  size_t i;

  for (i = 0; i < n; i++) {
    if (xp[i] != yp[i])
      return (int)xp[i] - (int)yp[i];
  }

  return 0;
}

int
btc_memcmp4(const void *x, size_t xn, const void *y, size_t yn) {
  size_t n = xn < yn ? xn : yn;

  if (n > 0) {
    int cmp = memcmp(x, y, n);

    if (cmp != 0)
      return cmp;
  }

  if (xn < yn)
    return -1;

  if (xn > yn)
    return 1;

  return 0;
}

/*
 * Memory Equal
 */

int
btc_memequal(const void *x, const void *y, size_t n) {
  const unsigned char *xp = (const unsigned char *)x;
  const unsigned char *yp = (const unsigned char *)y;
  uint32_t z = 0;

  while (n--)
    z |= *xp++ ^ *yp++;

  return (z - 1) >> 31;
}

/*
 * Memory XOR
 */

void
btc_memxor(void *z, const void *x, size_t n) {
  const unsigned char *xp = (const unsigned char *)x;
  unsigned char *zp = (unsigned char *)z;

  while (n--)
    *zp++ ^= *xp++;
}

void
btc_memxor3(void *z, const void *x, const void *y, size_t n) {
  const unsigned char *xp = (const unsigned char *)x;
  const unsigned char *yp = (const unsigned char *)y;
  unsigned char *zp = (unsigned char *)z;

  while (n--)
    *zp++ = *xp++ ^ *yp++;
}

/*
 * Memory Duplication
 */

void *
btc_memdup(const void *xp, size_t xn) {
  return memcpy(btc_malloc(xn), xp, xn);
}

/*
 * String
 */

size_t
btc_strnlen(const char *xp, size_t max) {
  size_t xn = 0;

  while (*xp++) {
    if (++xn == max)
      break;
  }

  return xn;
}

char *
btc_strdup(const char *xp) {
  return (char *)btc_memdup(xp, strlen(xp) + 1);
}

/*
 * Hash
 */

uint8_t *
btc_hash_clone(const uint8_t *xp) {
  return (uint8_t *)memcpy(btc_malloc(32), xp, 32);
}

int
btc_hash_compare(const uint8_t *xp, const uint8_t *yp) {
  int i;

  for (i = 32 - 1; i >= 0; i--) {
    if (xp[i] != yp[i])
      return (int)xp[i] - (int)yp[i];
  }

  return 0;
}

int
btc_hash_is_null(const uint8_t *xp) {
  static const uint8_t yp[32] = {0};
  return btc_hash_equal(xp, yp);
}

int
btc_hash_import(uint8_t *zp, const char *xp) {
  if (btc_strnlen(xp, 65) != 64)
    return 0;

  return btc_base16le_decode(zp, xp, 64);
}

void
btc_hash_export(char *zp, const uint8_t *xp) {
  btc_base16le_encode(zp, xp, 32);
}

/*
 * Time
 */

int64_t
btc_now(void) {
  time_t now = time(NULL);

  CHECK(now != (time_t)-1);

  return (int64_t)now;
}

/*
 * PoW
 */

double
btc_difficulty(uint32_t bits) {
  double diff = (double)0x0000ffff / (double)(bits & 0x00ffffff);
  int shift = (bits >> 24) & 0xff;

  while (shift < 29) {
    diff *= 256.0;
    shift++;
  }

  while (shift > 29) {
    diff /= 256.0;
    shift--;
  }

  return diff;
}
