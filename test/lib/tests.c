/*!
 * tests.c - test utils for mako
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/mako
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <mako/encoding.h>
#include "tests.h"

TEST_NORETURN void
test_assert_fail(const char *file, int line, const char *expr) {
  fprintf(stderr, "%s:%d: Assertion `%s' failed.\n", file, line, expr);
  fflush(stderr);
  abort();
}

void
hex_parse(unsigned char *zp, size_t zn, const char *xp) {
  size_t xn = strlen(xp);

  ASSERT(xn == zn * 2);
  ASSERT(btc_base16_decode(zp, xp, xn));
}

void
hex_decode(unsigned char *zp, size_t *zn, const char *xp) {
  size_t xn = strlen(xp);

  ASSERT(xn <= *zn * 2);
  ASSERT(btc_base16_decode(zp, xp, xn));

  *zn = xn / 2;
}
