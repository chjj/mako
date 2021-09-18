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
#include <satoshi/util.h>
#include "printf.h"

/*
 * Helpers
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

  *z++ = '.';

  z += btc_unsigned(z, lo);

  return z - s;
}

/*
 * STDIO
 */

void
btc_putc(int ch) {
  fputc(ch, stdout);
}

void
btc_fputc(FILE *stream, int ch) {
  fputc(ch, stream);
}

void
btc_puts(const char *str) {
  fputs(str, stdout);
}

void
btc_fputs(FILE *stream, const char *str) {
  fputs(str, stream);
}

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
btc_fprintf(FILE *stream, const char *fmt, ...) {
  va_list ap;
  int ret;

  va_start(ap, fmt);

  ret = btc_vfprintf(stream, fmt, ap);

  va_end(ap);

  return ret;
}

int
btc_vprintf(const char *fmt, va_list ap) {
  return btc_vfprintf(stdout, fmt, ap);
}

int
btc_vfprintf(FILE *stream, const char *fmt, va_list ap) {
  const char *str = fmt;
  char buf[1024];
  char *ptr = buf;
  int state = 0;
  int total = 0;

#define FLUSH do {        \
  if (ptr != buf) {       \
    *ptr = '\0';          \
    fputs(buf, stream);   \
    total += (ptr - buf); \
    ptr = buf;            \
  }                       \
} while (0)

#define NEED(n) do {                               \
  if ((size_t)(ptr - buf) + (n) > sizeof(buf) - 1) \
    FLUSH;                                         \
} while (0)

  while (*str) {
    int ch = *str++;

    switch (state) {
      case 0: {
        switch (ch) {
          case '%': {
            state = 1;
            break;
          }
          default: {
            NEED(1);
            *ptr++ = ch;
            if (ch == '\n') FLUSH;
            break;
          }
        }
        break;
      }
      case 1: {
        switch (ch) {
          case 'd':
          case 'i': {
            NEED(11);
            ptr += btc_signed(ptr, va_arg(ap, int));
            state = 0;
            break;
          }
          case 'o': {
            NEED(11);
            ptr += btc_octal(ptr, va_arg(ap, unsigned int));
            state = 0;
            break;
          }
          case 'u': {
            NEED(10);
            ptr += btc_unsigned(ptr, va_arg(ap, unsigned int));
            state = 0;
            break;
          }
          case 'x': {
            NEED(8);
            ptr += btc_hex(ptr, va_arg(ap, unsigned int), 'a');
            state = 0;
            break;
          }
          case 'X': {
            NEED(8);
            ptr += btc_hex(ptr, va_arg(ap, unsigned int), 'A');
            state = 0;
            break;
          }
          case 'f': {
            NEED(32);
            ptr += btc_float(ptr, va_arg(ap, double));
            state = 0;
            break;
          }
          case 'c': {
            NEED(1);
            *ptr++ = va_arg(ap, int);
            state = 0;
            break;
          }
          case 's': {
            FLUSH;
            fputs(va_arg(ap, char *), stream);
            state = 0;
            break;
          }
          case 'p': {
#if defined(UINTPTR_MAX)
            NEED(18);
            ptr += btc_ptr(ptr, va_arg(ap, void *));
#else
            abort();
#endif
            state = 0;
            break;
          }
          case 'n': {
            *(va_arg(ap, int *)) = total + (ptr - buf);
            break;
          }
          case '%': {
            NEED(1);
            *ptr++ = '%';
            state = 0;
            break;
          }
          case 'z': {
            if (*str == '\0') {
              state = 0;
              break;
            }

            ch = *str++;

            switch (ch) {
              case 'd':
              case 'i': {
#if defined(SIZE_MAX) && defined(INT64_MAX)
#  if SIZE_MAX >> 31 >> 31 >> 1 == 1
                NEED(21);
                ptr += btc_signed(ptr, va_arg(ap, int64_t));
#  else
                NEED(11);
                ptr += btc_signed(ptr, va_arg(ap, int32_t));
#  endif
#else
                abort();
#endif
                state = 0;
                break;
              }
              case 'o': {
                NEED(22);
                ptr += btc_octal(ptr, va_arg(ap, size_t));
                state = 0;
                break;
              }
              case 'u': {
                NEED(20);
                ptr += btc_unsigned(ptr, va_arg(ap, size_t));
                state = 0;
                break;
              }
              case 'x': {
                NEED(16);
                ptr += btc_hex(ptr, va_arg(ap, size_t), 'a');
                state = 0;
                break;
              }
              case 'X': {
                NEED(16);
                ptr += btc_hex(ptr, va_arg(ap, size_t), 'A');
                state = 0;
                break;
              }
              default: {
                state = 0;
                break;
              }
            }

            break;
          }
          case 'H': {
            /* 256-bit hash (little endian) */
            NEED(64);
            ptr += btc_hash(ptr, va_arg(ap, const unsigned char *));
            state = 0;
            break;
          }
          case 'T': {
            /* time value */
            NEED(21);
            ptr += btc_signed(ptr, va_arg(ap, int64_t));
            state = 0;
            break;
          }
          case 'v': {
            /* bitcoin amount */
            NEED(22);
            ptr += btc_value(ptr, va_arg(ap, int64_t));
            state = 0;
            break;
          }
          case 'q': {
            state = 3;
            break;
          }
          case 'l': {
            state = 2;
            break;
          }
          default: {
            state = 0;
            break;
          }
        }
        break;
      }
      case 2: {
        switch (ch) {
          case 'd':
          case 'i': {
            NEED(21);
            ptr += btc_signed(ptr, va_arg(ap, long));
            state = 0;
            break;
          }
          case 'o': {
            NEED(22);
            ptr += btc_octal(ptr, va_arg(ap, unsigned long));
            state = 0;
            break;
          }
          case 'u': {
            NEED(20);
            ptr += btc_unsigned(ptr, va_arg(ap, unsigned long));
            state = 0;
            break;
          }
          case 'x': {
            NEED(16);
            ptr += btc_hex(ptr, va_arg(ap, unsigned long), 'a');
            state = 0;
            break;
          }
          case 'X': {
            NEED(16);
            ptr += btc_hex(ptr, va_arg(ap, unsigned long), 'A');
            state = 0;
            break;
          }
          case 'l': {
            state = 3;
            break;
          }
          default: {
            state = 0;
            break;
          }
        }
        break;
      }
      case 3: {
        switch (ch) {
          case 'd':
          case 'i': {
            NEED(21);
            ptr += btc_signed(ptr, va_arg(ap, long long));
            state = 0;
            break;
          }
          case 'o': {
            NEED(22);
            ptr += btc_octal(ptr, va_arg(ap, unsigned long long));
            state = 0;
            break;
          }
          case 'u': {
            NEED(20);
            ptr += btc_unsigned(ptr, va_arg(ap, unsigned long long));
            state = 0;
            break;
          }
          case 'x': {
            NEED(16);
            ptr += btc_hex(ptr, va_arg(ap, unsigned long long), 'a');
            state = 0;
            break;
          }
          case 'X': {
            NEED(16);
            ptr += btc_hex(ptr, va_arg(ap, unsigned long long), 'A');
            state = 0;
            break;
          }
          default: {
            state = 0;
            break;
          }
        }
        break;
      }
    }
  }

  FLUSH;

#undef FLUSH
#undef NEED

  return total;
}
