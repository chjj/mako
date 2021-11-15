/*!
 * internal.c - internal utils for mako
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
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
btc_assert_fail(const char *file, int line, const char *expr) {
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
btc_abort(void) {
  abort(); /* LCOV_EXCL_LINE */
}

BTC_MALLOC void *
btc_malloc(size_t size) {
  void *ptr = malloc(size);

  if (ptr == NULL)
    abort(); /* LCOV_EXCL_LINE */

  return ptr;
}

BTC_MALLOC void *
btc_realloc(void *ptr, size_t size) {
  ptr = realloc(ptr, size);

  if (ptr == NULL)
    abort(); /* LCOV_EXCL_LINE */

  return ptr;
}

void
btc_free(void *ptr) {
  if (ptr == NULL) {
    abort(); /* LCOV_EXCL_LINE */
    return;
  }

  free(ptr);
}
