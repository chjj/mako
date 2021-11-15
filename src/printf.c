/*!
 * printf.c - printf for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <mako/printf.h>
#include "printf_core.h"

/*
 * Callbacks
 */

static void
state_fprintf(state_t *st, const char *xp, size_t xn) {
  fwrite(xp, 1, xn, st->stream);
  st->total += xn;
}

/*
 * Print
 */

int
btc_printf(const char *fmt, ...) {
  va_list ap;
  int ret;

  va_start(ap, fmt);

  ret = btc_vprintf(fmt, ap);

  va_end(ap);

  return ret;
}

int
btc_vprintf(const char *fmt, va_list ap) {
  return btc_vfprintf(stdout, fmt, ap);
}

int
btc_fprintf(FILE *stream, const char *fmt, ...) {
  va_list ap;
  int ret;

  va_start(ap, fmt);

  ret = btc_vfprintf(stream, fmt, ap);

  va_end(ap);

  return ret;
}

int
btc_vfprintf(FILE *stream, const char *fmt, va_list ap) {
  state_t st;

  st.stream = stream;
  st.str = NULL;
  st.size = 0;
  st.ptr = st.buf;
  st.state = PRINTF_STATE_NONE;
  st.total = 0;
  st.overflow = 1;
  st.flags = 0;
  st.prec = 0;
  st.width = 0;
  st.write = state_fprintf;

  return btc_printf_core(&st, fmt, ap);
}
