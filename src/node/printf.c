/*!
 * printf.c - printf for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <satoshi/util.h>
#include "printf.h"

/*
 * Serialization
 */

static int
btc_unsigned(char *z, unsigned long long x) {
  unsigned long long t = x;
  int n = 0;
  int i;

  do {
    z[n++] = '0';
    t /= 10;
  } while (t != 0);

  z[n] = '\0';

  for (i = n - 1; i >= 0; i--) {
    z[i] += (int)(x % 10);
    x /= 10;
  }

  return n;
}

static int
btc_signed(char *z, long long x) {
  if (x < 0) {
    *z++ = '-';

#if defined(LLONG_MIN) && defined(ULLONG_MAX)
    if (x == LLONG_MIN)
      return 1 + btc_unsigned(z, ULLONG_MAX / 2 + 1);
#endif

    return 1 + btc_unsigned(z, -x);
  }

  return btc_unsigned(z, x);
}

static int
btc_octal(char *z, unsigned long long x) {
  unsigned long long t = x;
  int n = 0;
  int i;

  do {
    z[n++] = '0';
    t >>= 3;
  } while (t != 0);

  z[n] = '\0';

  for (i = n - 1; i >= 0; i--) {
    z[i] += (int)(x & 7);
    x >>= 3;
  }

  return n;
}

static int
btc_hex(char *z, unsigned long long x, int c) {
  unsigned long long t = x;
  int n = 0;
  int i, ch;

  do {
    n++;
    t >>= 4;
  } while (t != 0);

  z[n] = '\0';

  for (i = n - 1; i >= 0; i--) {
    ch = x & 15;

    if (ch >= 10)
      ch += (c - 10);
    else
      ch += '0';

    z[i] = ch;

    x >>= 4;
  }

  return n;
}

static int
btc_float(char *z, double x) {
  /* Hard to do without -lm. */
  return sprintf(z, "%f", x);
}

#ifdef UINTPTR_MAX
static int
btc_ptr(char *z, void *ptr) {
  uintptr_t x = (uintptr_t)ptr;
  int n = sizeof(x) * CHAR_BIT + 2;
  int i, ch;

  z[n] = '\0';

  for (i = n - 1; i >= 2; i--) {
    ch = x & 15;

    if (ch >= 10)
      ch += ('a' - 10);
    else
      ch += '0';

    z[i] = ch;

    x >>= 4;
  }

  z[1] = 'x';
  z[0] = '0';

  return n;
}
#endif

static int
btc_hash(char *z, const unsigned char *hash) {
  btc_hash_export(z, hash);
  return 64;
}

static int
btc_value(char *z, int64_t x) {
  uint64_t hi, lo;
  char *s = z;

  if (x < 0) {
    *z++ = '-';
    x = -x;
  }

  hi = (uint64_t)x / 100000000;
  lo = (uint64_t)x % 100000000;

  z += btc_unsigned(z, hi);

  if (lo != 0) {
    *z++ = '.';
    z += btc_unsigned(z, lo);
  }

  return z - s;
}

/*
 * State Management
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
  void (*write)(struct state_s *, const char *, size_t);
} state_t;

static void
state_fprintf(state_t *st, const char *xp, size_t xn) {
  fwrite(xp, 1, xn, st->stream);
  st->total += xn;
}

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

static void
state_puts(state_t *st, const char *s) {
  if (s == NULL)
    s = "(null)";

  st->write(st, s, strlen(s));
}

static void
state_flush(state_t *st) {
  if (st->ptr != st->buf) {
    st->write(st, st->buf, st->ptr - st->buf);
    st->ptr = st->buf;
  }
}

static void
state_need(state_t *st, size_t n) {
  if ((size_t)(st->ptr - st->buf) + n > sizeof(st->buf) - 1)
    state_flush(st);
}

/*
 * Core
 */

static int
printf_core(state_t *st, const char *fmt, va_list ap) {
  while (*fmt) {
    int ch = *fmt++;

    switch (st->state) {
      case 0: {
        switch (ch) {
          case '%': {
            st->state = 1;
            break;
          }
          default: {
            state_need(st, 1);
            *st->ptr++ = ch;
            if (ch == '\n' && st->stream != NULL)
              state_flush(st);
            break;
          }
        }
        break;
      }
      case 1: {
        switch (ch) {
          case '%': {
            state_need(st, 1);
            *st->ptr++ = '%';
            st->state = 0;
            break;
          }
          case 'd':
          case 'i': {
            state_need(st, 11);
            st->ptr += btc_signed(st->ptr, va_arg(ap, int));
            st->state = 0;
            break;
          }
          case 'o': {
            state_need(st, 11);
            st->ptr += btc_octal(st->ptr, va_arg(ap, unsigned int));
            st->state = 0;
            break;
          }
          case 'u': {
            state_need(st, 10);
            st->ptr += btc_unsigned(st->ptr, va_arg(ap, unsigned int));
            st->state = 0;
            break;
          }
          case 'x': {
            state_need(st, 8);
            st->ptr += btc_hex(st->ptr, va_arg(ap, unsigned int), 'a');
            st->state = 0;
            break;
          }
          case 'X': {
            state_need(st, 8);
            st->ptr += btc_hex(st->ptr, va_arg(ap, unsigned int), 'A');
            st->state = 0;
            break;
          }
          case 'f': {
            state_need(st, 32);
            st->ptr += btc_float(st->ptr, va_arg(ap, double));
            st->state = 0;
            break;
          }
          case 'c': {
            state_need(st, 1);
            *st->ptr++ = va_arg(ap, int);
            st->state = 0;
            break;
          }
          case 's': {
            state_flush(st);
            state_puts(st, va_arg(ap, char *));
            st->state = 0;
            break;
          }
          case 'p': {
#if defined(UINTPTR_MAX)
            state_need(st, 18);
            st->ptr += btc_ptr(st->ptr, va_arg(ap, void *));
#else
            abort();
#endif
            st->state = 0;
            break;
          }
          case 'n': {
            *(va_arg(ap, int *)) = st->total + (st->ptr - st->buf);
            break;
          }
          case 'z': {
            if (*fmt == '\0') {
              st->state = 0;
              break;
            }

            ch = *fmt++;

            switch (ch) {
              case 'd':
              case 'i': {
#if defined(SIZE_MAX) && defined(INT64_MAX)
#  if SIZE_MAX >> 31 >> 31 >> 1 == 1
                state_need(st, 21);
                st->ptr += btc_signed(st->ptr, va_arg(ap, int64_t));
#  else
                state_need(st, 11);
                st->ptr += btc_signed(st->ptr, va_arg(ap, int32_t));
#  endif
#else
                abort();
#endif
                st->state = 0;
                break;
              }
              case 'o': {
                state_need(st, 22);
                st->ptr += btc_octal(st->ptr, va_arg(ap, size_t));
                st->state = 0;
                break;
              }
              case 'u': {
                state_need(st, 20);
                st->ptr += btc_unsigned(st->ptr, va_arg(ap, size_t));
                st->state = 0;
                break;
              }
              case 'x': {
                state_need(st, 16);
                st->ptr += btc_hex(st->ptr, va_arg(ap, size_t), 'a');
                st->state = 0;
                break;
              }
              case 'X': {
                state_need(st, 16);
                st->ptr += btc_hex(st->ptr, va_arg(ap, size_t), 'A');
                st->state = 0;
                break;
              }
              default: {
                st->state = 0;
                break;
              }
            }

            break;
          }
          case 'H': {
            /* 256-bit hash (little endian) */
            state_need(st, 64);
            st->ptr += btc_hash(st->ptr, va_arg(ap, unsigned char *));
            st->state = 0;
            break;
          }
          case 'T': {
            /* time value */
            state_need(st, 21);
            st->ptr += btc_signed(st->ptr, va_arg(ap, int64_t));
            st->state = 0;
            break;
          }
          case 'v': {
            /* bitcoin amount */
            state_need(st, 22);
            st->ptr += btc_value(st->ptr, va_arg(ap, int64_t));
            st->state = 0;
            break;
          }
          case 'q': {
            st->state = 3;
            break;
          }
          case 'l': {
            st->state = 2;
            break;
          }
          default: {
            st->state = 0;
            break;
          }
        }
        break;
      }
      case 2: {
        switch (ch) {
          case 'd':
          case 'i': {
            state_need(st, 21);
            st->ptr += btc_signed(st->ptr, va_arg(ap, long));
            st->state = 0;
            break;
          }
          case 'o': {
            state_need(st, 22);
            st->ptr += btc_octal(st->ptr, va_arg(ap, unsigned long));
            st->state = 0;
            break;
          }
          case 'u': {
            state_need(st, 20);
            st->ptr += btc_unsigned(st->ptr, va_arg(ap, unsigned long));
            st->state = 0;
            break;
          }
          case 'x': {
            state_need(st, 16);
            st->ptr += btc_hex(st->ptr, va_arg(ap, unsigned long), 'a');
            st->state = 0;
            break;
          }
          case 'X': {
            state_need(st, 16);
            st->ptr += btc_hex(st->ptr, va_arg(ap, unsigned long), 'A');
            st->state = 0;
            break;
          }
          case 'l': {
            st->state = 3;
            break;
          }
          default: {
            st->state = 0;
            break;
          }
        }
        break;
      }
      case 3: {
        switch (ch) {
          case 'd':
          case 'i': {
            state_need(st, 21);
            st->ptr += btc_signed(st->ptr, va_arg(ap, long long));
            st->state = 0;
            break;
          }
          case 'o': {
            state_need(st, 22);
            st->ptr += btc_octal(st->ptr, va_arg(ap, unsigned long long));
            st->state = 0;
            break;
          }
          case 'u': {
            state_need(st, 20);
            st->ptr += btc_unsigned(st->ptr, va_arg(ap, unsigned long long));
            st->state = 0;
            break;
          }
          case 'x': {
            state_need(st, 16);
            st->ptr += btc_hex(st->ptr, va_arg(ap, unsigned long long), 'a');
            st->state = 0;
            break;
          }
          case 'X': {
            state_need(st, 16);
            st->ptr += btc_hex(st->ptr, va_arg(ap, unsigned long long), 'A');
            st->state = 0;
            break;
          }
          default: {
            st->state = 0;
            break;
          }
        }
        break;
      }
    }
  }

  state_flush(st);

  return st->total;
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
  st.state = 0;
  st.total = 0;
  st.overflow = 1;
  st.write = state_fprintf;

  return printf_core(&st, fmt, ap);
}

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
  st.state = 0;
  st.total = 0;
  st.overflow = (str == NULL);
  st.write = state_sprintf;

  return printf_core(&st, fmt, ap);
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
  st.state = 0;
  st.total = 0;
  st.overflow = (str == NULL || size == 0);
  st.write = state_snprintf;

  return printf_core(&st, fmt, ap);
}
