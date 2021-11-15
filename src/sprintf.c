/*!
 * sprintf.c - sprintf for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <mako/printf.h>
#include "printf_core.h"

/*
 * Callbacks
 */

static void
state_sprintf(state_t *st, const char *xp, size_t xn) {
  if (st->str != NULL) {
    memcpy(st->str, xp, xn);
    st->str += xn;
    *st->str = '\0';
  }

  st->total += xn;
}

static void
state_snprintf(state_t *st, const char *xp, size_t xn) {
  st->total += xn;

  if (!st->overflow) {
    if (xn > st->size - 1) {
      xn = st->size - 1;
      st->overflow = 1;
    }

    memcpy(st->str, xp, xn);

    st->str += xn;
    st->size -= xn;

    *st->str = '\0';
  }
}

/*
 * Print
 */

int
btc_sprintf(char *str, const char *fmt, ...) {
  va_list ap;
  int ret;

  va_start(ap, fmt);

  ret = btc_vsprintf(str, fmt, ap);

  va_end(ap);

  return ret;
}

int
btc_vsprintf(char *str, const char *fmt, va_list ap) {
  state_t st;

  st.stream = NULL;
  st.str = str;
  st.size = 0;
  st.ptr = st.buf;
  st.state = PRINTF_STATE_NONE;
  st.total = 0;
  st.overflow = (str == NULL);
  st.flags = 0;
  st.prec = 0;
  st.width = 0;
  st.write = state_sprintf;

  return btc_printf_core(&st, fmt, ap);
}

int
btc_snprintf(char *str, size_t size, const char *fmt, ...) {
  va_list ap;
  int ret;

  va_start(ap, fmt);

  ret = btc_vsnprintf(str, size, fmt, ap);

  va_end(ap);

  return ret;
}

int
btc_vsnprintf(char *str, size_t size, const char *fmt, va_list ap) {
  state_t st;

  st.stream = NULL;
  st.str = str;
  st.size = size;
  st.ptr = st.buf;
  st.state = PRINTF_STATE_NONE;
  st.total = 0;
  st.overflow = (str == NULL || size == 0);
  st.flags = 0;
  st.prec = 0;
  st.width = 0;
  st.write = state_snprintf;

  return btc_printf_core(&st, fmt, ap);
}
