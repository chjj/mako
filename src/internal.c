/*!
 * internal.c - internal utils for libsatoshi
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <limits.h>
#ifdef BTC_DEBUG
#  include <stdio.h>
#endif
#include <stdlib.h>
#include "internal.h"

/*
 * Helpers
 */

BTC_NORETURN void
btc__assert_fail(const char *file, int line, const char *expr) {
  /* LCOV_EXCL_START */
#if defined(BTC_DEBUG)
  fprintf(stderr, "%s:%d: Assertion `%s' failed.\n", file, line, expr);
  fflush(stderr);
#else
  (void)file;
  (void)line;
  (void)expr;
#endif
  abort();
  /* LCOV_EXCL_STOP */
}

BTC_NORETURN void
btc__abort(void) {
  abort(); /* LCOV_EXCL_LINE */
}
