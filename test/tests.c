/*!
 * tests.c - test utils for libsatoshi
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libsatoshi
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
char2nib(int ch) {
  if (ch >= '0' && ch <= '9')
    ch -= '0';
  else if (ch >= 'A' && ch <= 'F')
    ch -= 'A' - 10;
  else if (ch >= 'a' && ch <= 'f')
    ch -= 'a' - 10;
  else
    ch = 16;

  return ch;
}

static int
unhex(unsigned char *out, const char *str, size_t len) {
  size_t j = 0;
  int hi, lo;
  size_t i;

  if (len & 1)
    return 0;

  for (i = 0; i < len; i += 2) {
    hi = char2nib(str[i + 0]);

    if (hi >= 16)
      return 0;

    lo = char2nib(str[i + 1]);

    if (lo >= 16)
      return 0;

    out[j++] = (hi << 4) | lo;
  }

  return 1;
}

void
hex_parse(unsigned char *out, size_t size, const char *str) {
  size_t len = strlen(str);

  ASSERT(len == size * 2);
  ASSERT(unhex(out, str, len));
}

void
hex_decode(unsigned char *out, size_t *size, const char *str) {
  size_t len = strlen(str);

  ASSERT(len <= *size * 2);
  ASSERT(unhex(out, str, len));

  *size = len / 2;
}
