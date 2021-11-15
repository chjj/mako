/*!
 * printf_core.c - printf for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <errno.h>
#include <limits.h>
#include <math.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <mako/netaddr.h>
#include <mako/printf.h>
#include "printf_core.h"

/*
 * Base16
 */

static const char *base16_charset = "0123456789abcdef";

static size_t
base16_encode(char *zp, const unsigned char *xp, size_t xn) {
  size_t zn = xn * 2;

  while (xn--) {
    int ch = *xp++;

    *zp++ = base16_charset[ch >> 4];
    *zp++ = base16_charset[ch & 15];
  }

  *zp = '\0';

  return zn;
}

static size_t
base16le_encode(char *zp, const unsigned char *xp, size_t xn) {
  size_t zn = xn * 2;

  xp += xn;

  while (xn--) {
    int ch = *--xp;

    *zp++ = base16_charset[ch >> 4];
    *zp++ = base16_charset[ch & 15];
  }

  *zp = '\0';

  return zn;
}

/*
 * State
 */

static void
state_puts(state_t *st, const char *xp) {
  size_t xn;

  if (xp == NULL)
    xp = "(null)";

  xn = strlen(xp);

  if (st->flags & PRINTF_PRECISION) {
    if (xn > (size_t)st->prec)
      xn = st->prec;

    if (xn == 0)
      return;
  }

  st->write(st, xp, xn);
}

static void
state_raw(state_t *st, const unsigned char *xp, size_t xn) {
  char zp[1024 + 1];

  while (xn >= 512) {
    st->write(st, zp, base16_encode(zp, xp, 512));

    xp += 512;
    xn -= 512;
  }

  if (xn > 0)
    st->write(st, zp, base16_encode(zp, xp, xn));
}

static void
state_flush(state_t *st) {
  if (st->ptr != st->buf) {
    st->write(st, st->buf, st->ptr - st->buf);
    st->ptr = st->buf;
  }
}

static void
state_grow(state_t *st, size_t n) {
  if ((size_t)(st->ptr - st->buf) + n > sizeof(st->buf) - 1)
    state_flush(st);
}

static void
state_need(state_t *st, size_t n) {
  if (st->flags & PRINTF_PRECISION) {
    if (n < (size_t)st->prec)
      n = st->prec;
  } else if (st->flags & PRINTF_WIDTH) {
    if (n < (size_t)st->width)
      n = st->width;
  }

  if (st->flags & (PRINTF_BLANK_POSITIVE | PRINTF_PLUS_MINUS))
    n += 1;

  if (st->flags & PRINTF_ALT_FORM)
    n += 2;

  state_grow(st, n);
}

/*
 * Serialization
 */

static int
btc_uint_size(unsigned long long x) {
  int n = 0;

  do {
    n++;
    x /= 10;
  } while (x != 0);

  return n;
}

static int
btc_uint_write(char *zp, unsigned long long x) {
  int n = btc_uint_size(x);
  int i;

  zp[n] = '\0';

  for (i = n - 1; i >= 0; i--) {
    zp[i] = '0' + (int)(x % 10);
    x /= 10;
  }

  return n;
}

static int
btc_unsigned(char *zp, unsigned long long x, const state_t *st) {
  int n = btc_uint_size(x);
  int i;

  if (st->flags & PRINTF_PRECISION) {
    if (n < st->prec)
      n = st->prec;
  }

  zp[n] = '\0';

  for (i = n - 1; i >= 0; i--) {
    zp[i] = '0' + (int)(x % 10);
    x /= 10;
  }

  return n;
}

static int
btc_signed(char *zp, long long x, const state_t *st) {
  int n = 0;

  if (x < 0) {
    *zp++ = '-';

#if defined(LLONG_MIN) && defined(ULLONG_MAX)
    if (x == LLONG_MIN)
      return 1 + btc_unsigned(zp, ULLONG_MAX / 2 + 1, st);
#endif

    return 1 + btc_unsigned(zp, -x, st);
  }

  if (st->flags & PRINTF_BLANK_POSITIVE) {
    *zp++ = ' ';
    n++;
  } else if (st->flags & PRINTF_PLUS_MINUS) {
    *zp++ = '+';
    n++;
  }

  return n + btc_unsigned(zp, x, st);
}

static int
btc_octal(char *zp, unsigned long long x, const state_t *st) {
  unsigned long long t = x;
  int n = 0;
  int i;

  do {
    n++;
    t >>= 3;
  } while (t != 0);

  if (st->flags & PRINTF_ALT_FORM)
    n++;

  if (st->flags & PRINTF_PRECISION) {
    if (n < st->prec)
      n = st->prec;
  }

  zp[n] = '\0';

  for (i = n - 1; i >= 0; i--) {
    zp[i] = '0' + (int)(x & 7);
    x >>= 3;
  }

  return n;
}

static int
btc_hex(char *zp, unsigned long long x, int u, const state_t *st) {
  const char *charset = u ? "0123456789ABCDEF" : "0123456789abcdef";
  unsigned long long t = x;
  int n = 0;
  int i;

  do {
    n++;
    t >>= 4;
  } while (t != 0);

  if (st->flags & PRINTF_PRECISION) {
    if (n < st->prec)
      n = st->prec;
  }

  if (st->flags & PRINTF_ALT_FORM)
    n += 2;

  zp[n] = '\0';

  for (i = n - 1; i >= 0; i--) {
    zp[i] = charset[x & 15];
    x >>= 4;
  }

  if (st->flags & PRINTF_ALT_FORM) {
    zp[1] = 'x';
    zp[0] = '0';
  }

  return n;
}

static int
btc_float(char *zp, double x, const state_t *st) {
  unsigned long long hi, lo;
  double frac, iptr;
  char *sp = zp;
  int prec = 6;
  int i;

  if (st->flags & PRINTF_PRECISION)
    prec = st->prec;

  if (x < 0.0) {
    *zp++ = '-';
    x = -x;
  }

  frac = modf(x, &iptr);
  hi = (unsigned long long)iptr;
  lo = (unsigned long long)(frac * pow(10, prec));

  zp += btc_uint_write(zp, hi);

  if (prec != 0) {
    *zp++ = '.';

    zp[prec] = '\0';

    for (i = prec - 1; i >= 0; i--) {
      zp[i] = '0' + (int)(lo % 10);
      lo /= 10;
    }

    zp += prec;
  }

  return zp - sp;
}

#ifdef UINTPTR_MAX
static int
btc_ptr(char *zp, void *xp) {
  uintptr_t x = (uintptr_t)xp;
  int n = ((sizeof(x) * CHAR_BIT) / 4) + 2;
  int i;

  zp[n] = '\0';

  for (i = n - 1; i >= 2; i--) {
    zp[i] = base16_charset[x & 15];
    x >>= 4;
  }

  zp[1] = 'x';
  zp[0] = '0';

  return n;
}
#endif

static int
btc_raw(char *zp, const unsigned char *xp, size_t xn) {
  return base16_encode(zp, xp, xn);
}

static int
btc_hash(char *zp, const unsigned char *xp) {
  if (xp == NULL) {
    strcpy(zp, "NULL");
    return 4;
  }

  return base16le_encode(zp, xp, 32);
}

static int
btc_date(char *zp, int64_t x) {
  /* https://stackoverflow.com/a/42936293 */
  /* https://howardhinnant.github.io/date_algorithms.html#civil_from_days */
  int zz = (x / 86400) + 719468;
  int era = (zz >= 0 ? zz : zz - 146096) / 146097;
  unsigned int doe = (unsigned int)(zz - era * 146097);
  unsigned int yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
  int y = (int)yoe + era * 400;
  unsigned int doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
  unsigned int mp = (5 * doy + 2) / 153;
  unsigned int d = doy - (153 * mp + 2) / 5 + 1;
  unsigned int m = mp < 10 ? mp + 3 : mp - 9;
  unsigned int hr = (x / 3600) % 24;
  unsigned int min = (x / 60) % 60;
  unsigned int sec = x % 60;

  y += (m <= 2);

  return btc_sprintf(zp, "%.4u-%.2u-%.2uT%.2u:%.2u:%.2uZ",
                         y, m, d, hr, min, sec);
}

static int
btc_value(char *zp, int64_t x) {
  uint64_t hi, lo;
  char *sp = zp;
  int n;

  if (x < 0) {
    *zp++ = '-';
    x = -x;
  }

  hi = (uint64_t)x / 100000000;
  lo = (uint64_t)x % 100000000;

  zp += btc_uint_write(zp, hi);

  if (lo != 0) {
    n = btc_uint_size(lo);

    *zp++ = '.';

    while (n < 8) {
      *zp++ = '0';
      n++;
    }

    while ((lo % 10) == 0)
      lo /= 10;

    zp += btc_uint_write(zp, lo);
  }

  return zp - sp;
}

static int
btc_addr(char *zp, const struct btc_sockaddr_s *x) {
  btc_netaddr_t z;
  btc_netaddr_set_sockaddr(&z, x);
  return btc_netaddr_get_str(zp, &z);
}

static int
btc_netaddr(char *zp, const btc_netaddr_t *x) {
  return btc_netaddr_get_str(zp, x);
}

/*
 * Helpers
 */

static int
clamp8(int x) {
  if (x < SCHAR_MIN)
    x = SCHAR_MIN;
  else if (x > SCHAR_MAX)
    x = SCHAR_MAX;
  return x;
}

static int
clamp16(int x) {
  if (x < SHRT_MIN)
    x = SHRT_MIN;
  else if (x > SHRT_MAX)
    x = SHRT_MAX;
  return x;
}

/*
 * Core
 */

int
btc_printf_core(state_t *st, const char *fmt, va_list ap) {
  while (*fmt) {
    int ch = *fmt++;

    switch (st->state) {
      case PRINTF_STATE_NONE: {
        switch (ch) {
          case '%': {
            st->state = PRINTF_STATE_FLAGS;
            st->flags = 0;
            st->prec = 0;
            st->width = 0;
            break;
          }
          default: {
            state_grow(st, 1);
            *st->ptr++ = ch;
            if (ch == '\n' && st->stream != NULL)
              state_flush(st);
            break;
          }
        }
        break;
      }
      case PRINTF_STATE_FLAGS: {
        switch (ch) {
          case '#': {
            st->flags |= PRINTF_ALT_FORM;
            break;
          }
          case '0': {
            st->flags |= PRINTF_ZERO_PAD;
            break;
          }
          case '-': {
            st->flags |= PRINTF_LEFT_JUSTIFY;
            break;
          }
          case ' ': {
            st->flags |= PRINTF_BLANK_POSITIVE;
            break;
          }
          case '+': {
            st->flags |= PRINTF_PLUS_MINUS;
            break;
          }
          case '.': {
            st->state = PRINTF_STATE_PRECISION;
            st->flags |= PRINTF_PRECISION;
            st->prec = 0;
            break;
          }
          default: {
            if (ch >= '1' && ch <= '9') {
              st->state = PRINTF_STATE_WIDTH;
              st->flags |= PRINTF_WIDTH;
              st->width = 0;
            } else {
              st->state = PRINTF_STATE_LENGTH;
            }
            fmt--;
            break;
          }
        }
        break;
      }
      case PRINTF_STATE_PRECISION: {
        if (ch < '0' || ch > '9') {
          st->state = PRINTF_STATE_FLAGS;
          fmt--;
          break;
        }
        st->prec *= 10;
        st->prec += (ch - '0');
        break;
      }
      case PRINTF_STATE_WIDTH: {
        if (ch < '0' || ch > '9') {
          st->state = PRINTF_STATE_FLAGS;
          fmt--;
          break;
        }
        st->width *= 10;
        st->width += (ch - '0');
        break;
      }
      case PRINTF_STATE_LENGTH: {
        switch (ch) {
          case 'h': {
            st->state = PRINTF_STATE_SHORT;
            break;
          }
          case 'l': {
            st->state = PRINTF_STATE_LONG;
            break;
          }
          case 'q': {
            st->state = PRINTF_STATE_LONGLONG;
            break;
          }
          case 'z':
          case 'Z': {
            st->state = PRINTF_STATE_SIZE;
            break;
          }
          default: {
            st->state = PRINTF_STATE_CONV;
            fmt--;
            break;
          }
        }
        break;
      }
      case PRINTF_STATE_CONV: {
        switch (ch) {
          case '%': {
            state_grow(st, 1);
            *st->ptr++ = '%';
            st->state = PRINTF_STATE_NONE;
            break;
          }
          case 'f': {
            state_need(st, 42);
            st->ptr += btc_float(st->ptr, va_arg(ap, double), st);
            st->state = PRINTF_STATE_NONE;
            break;
          }
          case 'c': {
            state_grow(st, 1);
            *st->ptr++ = va_arg(ap, int);
            st->state = PRINTF_STATE_NONE;
            break;
          }
          case 's': {
            state_flush(st);
            state_puts(st, va_arg(ap, char *));
            st->state = PRINTF_STATE_NONE;
            break;
          }
          case 'p': {
#if defined(UINTPTR_MAX)
            state_grow(st, 18);
            st->ptr += btc_ptr(st->ptr, va_arg(ap, void *));
#else
            abort();
#endif
            st->state = PRINTF_STATE_NONE;
            break;
          }
          case 'm': {
            state_flush(st);
            state_puts(st, strerror(errno));
            st->state = PRINTF_STATE_NONE;
            break;
          }
          case 'R': {
            /* raw data */
            unsigned char *raw = va_arg(ap, unsigned char *);

            if (st->flags & PRINTF_PRECISION) {
              if ((size_t)st->prec >= sizeof(st->buf) / 2)
                abort();

              state_grow(st, st->prec * 2);
              st->ptr += btc_raw(st->ptr, raw, st->prec);
            } else {
              state_flush(st);
              state_raw(st, raw, va_arg(ap, size_t));
            }

            st->state = PRINTF_STATE_NONE;

            break;
          }
          case 'H': {
            /* 256-bit hash (little endian) */
            state_grow(st, 64);
            st->ptr += btc_hash(st->ptr, va_arg(ap, unsigned char *));
            st->state = PRINTF_STATE_NONE;
            break;
          }
          case 'T': {
            /* time value */
            state_need(st, 21);
            st->ptr += btc_signed(st->ptr, va_arg(ap, int64_t), st);
            st->state = PRINTF_STATE_NONE;
            break;
          }
          case 'D': {
            /* date */
            state_grow(st, 66);
            st->ptr += btc_date(st->ptr, va_arg(ap, int64_t));
            st->state = PRINTF_STATE_NONE;
            break;
          }
          case 'v': {
            /* bitcoin amount */
            state_grow(st, 22);
            st->ptr += btc_value(st->ptr, va_arg(ap, int64_t));
            st->state = PRINTF_STATE_NONE;
            break;
          }
          case 'S': {
            /* socket address */
            state_grow(st, BTC_ADDRSTRLEN);
            st->ptr += btc_addr(st->ptr, va_arg(ap, struct btc_sockaddr_s *));
            st->state = PRINTF_STATE_NONE;
            break;
          }
          case 'N': {
            /* network address */
            state_grow(st, BTC_ADDRSTRLEN);
            st->ptr += btc_netaddr(st->ptr, va_arg(ap, btc_netaddr_t *));
            st->state = PRINTF_STATE_NONE;
            break;
          }
          default: {
            st->state = PRINTF_STATE_INT;
            fmt--;
            break;
          }
        }
        break;
      }
      case PRINTF_STATE_CHAR: {
        switch (ch) {
          case 'd':
          case 'i': {
            state_need(st, 4);
            st->ptr += btc_signed(st->ptr, clamp8(va_arg(ap, int)), st);
            st->state = PRINTF_STATE_NONE;
            break;
          }
          case 'o': {
            state_need(st, 3);
            st->ptr += btc_octal(st->ptr, va_arg(ap, unsigned) & 0xff, st);
            st->state = PRINTF_STATE_NONE;
            break;
          }
          case 'u': {
            state_need(st, 3);
            st->ptr += btc_unsigned(st->ptr, va_arg(ap, unsigned) & 0xff, st);
            st->state = PRINTF_STATE_NONE;
            break;
          }
          case 'x': {
            state_need(st, 2);
            st->ptr += btc_hex(st->ptr, va_arg(ap, unsigned) & 0xff, 0, st);
            st->state = PRINTF_STATE_NONE;
            break;
          }
          case 'X': {
            state_need(st, 2);
            st->ptr += btc_hex(st->ptr, va_arg(ap, unsigned) & 0xff, 1, st);
            st->state = PRINTF_STATE_NONE;
            break;
          }
          case 'n': {
            *(va_arg(ap, char *)) = (st->total + (st->ptr - st->buf)) & 0x7f;
            st->state = PRINTF_STATE_NONE;
            break;
          }
          default: {
            st->state = PRINTF_STATE_NONE;
            break;
          }
        }
        break;
      }
      case PRINTF_STATE_SHORT: {
        switch (ch) {
          case 'd':
          case 'i': {
            state_need(st, 6);
            st->ptr += btc_signed(st->ptr, clamp16(va_arg(ap, int)), st);
            st->state = PRINTF_STATE_NONE;
            break;
          }
          case 'o': {
            state_need(st, 6);
            st->ptr += btc_octal(st->ptr, va_arg(ap, unsigned) & 0xffff, st);
            st->state = PRINTF_STATE_NONE;
            break;
          }
          case 'u': {
            state_need(st, 5);
            st->ptr += btc_unsigned(st->ptr, va_arg(ap, unsigned) & 0xffff, st);
            st->state = PRINTF_STATE_NONE;
            break;
          }
          case 'x': {
            state_need(st, 4);
            st->ptr += btc_hex(st->ptr, va_arg(ap, unsigned) & 0xffff, 0, st);
            st->state = PRINTF_STATE_NONE;
            break;
          }
          case 'X': {
            state_need(st, 4);
            st->ptr += btc_hex(st->ptr, va_arg(ap, unsigned) & 0xffff, 1, st);
            st->state = PRINTF_STATE_NONE;
            break;
          }
          case 'n': {
            *(va_arg(ap, short *)) = (st->total + (st->ptr - st->buf)) & 0x7fff;
            st->state = PRINTF_STATE_NONE;
            break;
          }
          case 'h': {
            st->state = PRINTF_STATE_CHAR;
            break;
          }
          default: {
            st->state = PRINTF_STATE_NONE;
            break;
          }
        }
        break;
      }
      case PRINTF_STATE_INT: {
        switch (ch) {
          case 'd':
          case 'i': {
            state_need(st, 11);
            st->ptr += btc_signed(st->ptr, va_arg(ap, int), st);
            st->state = PRINTF_STATE_NONE;
            break;
          }
          case 'o': {
            state_need(st, 11);
            st->ptr += btc_octal(st->ptr, va_arg(ap, unsigned int), st);
            st->state = PRINTF_STATE_NONE;
            break;
          }
          case 'u': {
            state_need(st, 10);
            st->ptr += btc_unsigned(st->ptr, va_arg(ap, unsigned int), st);
            st->state = PRINTF_STATE_NONE;
            break;
          }
          case 'x': {
            state_need(st, 8);
            st->ptr += btc_hex(st->ptr, va_arg(ap, unsigned int), 0, st);
            st->state = PRINTF_STATE_NONE;
            break;
          }
          case 'X': {
            state_need(st, 8);
            st->ptr += btc_hex(st->ptr, va_arg(ap, unsigned int), 1, st);
            st->state = PRINTF_STATE_NONE;
            break;
          }
          case 'n': {
            *(va_arg(ap, int *)) = st->total + (st->ptr - st->buf);
            st->state = PRINTF_STATE_NONE;
            break;
          }
          default: {
            st->state = PRINTF_STATE_NONE;
            break;
          }
        }
        break;
      }
      case PRINTF_STATE_LONG: {
        switch (ch) {
          case 'd':
          case 'i': {
            state_need(st, 21);
            st->ptr += btc_signed(st->ptr, va_arg(ap, long), st);
            st->state = PRINTF_STATE_NONE;
            break;
          }
          case 'o': {
            state_need(st, 22);
            st->ptr += btc_octal(st->ptr, va_arg(ap, unsigned long), st);
            st->state = PRINTF_STATE_NONE;
            break;
          }
          case 'u': {
            state_need(st, 20);
            st->ptr += btc_unsigned(st->ptr, va_arg(ap, unsigned long), st);
            st->state = PRINTF_STATE_NONE;
            break;
          }
          case 'x': {
            state_need(st, 16);
            st->ptr += btc_hex(st->ptr, va_arg(ap, unsigned long), 0, st);
            st->state = PRINTF_STATE_NONE;
            break;
          }
          case 'X': {
            state_need(st, 16);
            st->ptr += btc_hex(st->ptr, va_arg(ap, unsigned long), 1, st);
            st->state = PRINTF_STATE_NONE;
            break;
          }
          case 'n': {
            *(va_arg(ap, long *)) = st->total + (st->ptr - st->buf);
            st->state = PRINTF_STATE_NONE;
            break;
          }
          case 'l': {
            st->state = PRINTF_STATE_LONGLONG;
            break;
          }
          default: {
            st->state = PRINTF_STATE_NONE;
            break;
          }
        }
        break;
      }
      case PRINTF_STATE_LONGLONG: {
        switch (ch) {
          case 'd':
          case 'i': {
            state_need(st, 21);
            st->ptr += btc_signed(st->ptr, va_arg(ap, long long), st);
            st->state = PRINTF_STATE_NONE;
            break;
          }
          case 'o': {
            state_need(st, 22);
            st->ptr += btc_octal(st->ptr, va_arg(ap, unsigned long long), st);
            st->state = PRINTF_STATE_NONE;
            break;
          }
          case 'u': {
            state_need(st, 20);
            st->ptr += btc_unsigned(st->ptr, va_arg(ap, unsigned long long), st);
            st->state = PRINTF_STATE_NONE;
            break;
          }
          case 'x': {
            state_need(st, 16);
            st->ptr += btc_hex(st->ptr, va_arg(ap, unsigned long long), 0, st);
            st->state = PRINTF_STATE_NONE;
            break;
          }
          case 'X': {
            state_need(st, 16);
            st->ptr += btc_hex(st->ptr, va_arg(ap, unsigned long long), 1, st);
            st->state = PRINTF_STATE_NONE;
            break;
          }
          case 'n': {
            *(va_arg(ap, long long *)) = st->total + (st->ptr - st->buf);
            st->state = PRINTF_STATE_NONE;
            break;
          }
          default: {
            st->state = PRINTF_STATE_NONE;
            break;
          }
        }
        break;
      }
      case PRINTF_STATE_SIZE: {
        switch (ch) {
          case 'd':
          case 'i': {
#if defined(SIZE_MAX) && defined(INT64_MAX)
#  if SIZE_MAX >> 31 >> 31 >> 1 == 1
            state_need(st, 21);
            st->ptr += btc_signed(st->ptr, va_arg(ap, int64_t), st);
#  else
            state_need(st, 11);
            st->ptr += btc_signed(st->ptr, va_arg(ap, int32_t), st);
#  endif
#else
            abort();
#endif
            st->state = PRINTF_STATE_NONE;
            break;
          }
          case 'o': {
            state_need(st, 22);
            st->ptr += btc_octal(st->ptr, va_arg(ap, size_t), st);
            st->state = PRINTF_STATE_NONE;
            break;
          }
          case 'u': {
            state_need(st, 20);
            st->ptr += btc_unsigned(st->ptr, va_arg(ap, size_t), st);
            st->state = PRINTF_STATE_NONE;
            break;
          }
          case 'x': {
            state_need(st, 16);
            st->ptr += btc_hex(st->ptr, va_arg(ap, size_t), 0, st);
            st->state = PRINTF_STATE_NONE;
            break;
          }
          case 'X': {
            state_need(st, 16);
            st->ptr += btc_hex(st->ptr, va_arg(ap, size_t), 1, st);
            st->state = PRINTF_STATE_NONE;
            break;
          }
          case 'n': {
            *(va_arg(ap, size_t *)) = st->total + (st->ptr - st->buf);
            st->state = PRINTF_STATE_NONE;
            break;
          }
          default: {
            st->state = PRINTF_STATE_NONE;
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
