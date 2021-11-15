/*!
 * printf_core.h - printf for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifndef BTC_PRINTF_CORE_H
#define BTC_PRINTF_CORE_H

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/*
 * Constants
 */

enum printf_state {
  PRINTF_STATE_NONE,
  PRINTF_STATE_FLAGS,
  PRINTF_STATE_WIDTH,
  PRINTF_STATE_PRECISION,
  PRINTF_STATE_LENGTH,
  PRINTF_STATE_CONV,
  PRINTF_STATE_CHAR,
  PRINTF_STATE_SHORT,
  PRINTF_STATE_INT,
  PRINTF_STATE_LONG,
  PRINTF_STATE_LONGLONG,
  PRINTF_STATE_SIZE
};

enum printf_flags {
  PRINTF_ALT_FORM = 1 << 0, /* # */
  PRINTF_ZERO_PAD = 1 << 1, /* 0 */
  PRINTF_LEFT_JUSTIFY = 1 << 2, /* - */
  PRINTF_BLANK_POSITIVE = 1 << 3, /* ' ' */
  PRINTF_PLUS_MINUS = 1 << 4, /* + */
  PRINTF_PRECISION = 1 << 5, /* . */
  PRINTF_WIDTH = 1 << 6 /* 1-9 */
};

/*
 * Types
 */

typedef struct state_s {
  FILE *stream;
  char *str;
  size_t size;
  char buf[1024];
  char *ptr;
  int state;
  size_t total;
  int overflow;
  int flags;
  int prec;
  int width;
  void (*write)(struct state_s *, const char *, size_t);
} state_t;

/*
 * Print
 */

int
btc_printf_core(state_t *st, const char *fmt, va_list ap);

#endif /* BTC_PRINTF_CORE_H */
