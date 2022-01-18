/*!
 * tests.c - test utils for mako
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/mako
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "tests.h"

TEST_NORETURN void
test_assert_fail(const char *file, int line, const char *expr) {
  fprintf(stderr, "%s:%d: Assertion `%s' failed.\n", file, line, expr);
  fflush(stderr);
  abort();
}

static int
base16_nibble(int ch) {
  if (ch >= '0' && ch <= '9')
    return ch - '0';

  if (ch >= 'A' && ch <= 'F')
    return ch - 'A' + 10;

  if (ch >= 'a' && ch <= 'f')
    return ch - 'a' + 10;

  return -1;
}

static int
base16_decode(unsigned char *zp, const char *xp, size_t xn) {
  int z = 0;

  if (xn & 1)
    return 0;

  xn >>= 1;

  while (xn--) {
    int hi = base16_nibble(*xp++);
    int lo = base16_nibble(*xp++);

    z |= hi | lo;

    *zp++ = (hi << 4) | lo;
  }

  return z >= 0;
}

void
hex_parse(unsigned char *zp, size_t zn, const char *xp) {
  size_t xn = strlen(xp);

  ASSERT(xn == zn * 2);
  ASSERT(base16_decode(zp, xp, xn));
}

void
hex_decode(unsigned char *zp, size_t *zn, const char *xp) {
  size_t xn = strlen(xp);

  ASSERT(xn <= *zn * 2);
  ASSERT(base16_decode(zp, xp, xn));

  *zn = xn / 2;
}
