/*!
 * amount.c - amount utils for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <mako/consensus.h>
#include <mako/util.h>
#include "internal.h"

/*
 * Constants
 */

#define BTC_MAX_COINS ((double)(BTC_MAX_MONEY / BTC_COIN))

/*
 * Helpers
 */

static int
size64(int64_t x) {
  int n = 0;

  do {
    n++;
    x /= 10;
  } while (x != 0);

  return n;
}

static int
encode64(char *zp, int64_t x) {
  int n = size64(x);
  int i;

  zp[n] = '\0';

  for (i = n - 1; i >= 0; i--) {
    zp[i] = '0' + (int)(x % 10);
    x /= 10;
  }

  return n;
}

static int
decode64(int64_t *z, const char **xp, int limit) {
  int n = 0;

  *z = 0;

  for (;;) {
    int ch = **xp;

    if (ch < '0' || ch > '9')
      break;

    if (++n > limit)
      return 0;

    *z *= 10;
    *z += (ch - '0');

    *xp += 1;
  }

  return n;
}

/*
 * Amount
 */

size_t
btc_amount_export(char *zp, int64_t x) {
  int64_t hi, lo;
  char *sp = zp;
  int n;

  if (x < 0) {
    *zp++ = '-';
    x = -x;
  }

  hi = x / BTC_COIN;
  lo = x % BTC_COIN;

  zp += encode64(zp, hi);

  if (lo != 0) {
    n = size64(lo);

    *zp++ = '.';

    while (n < BTC_PRECISION) {
      *zp++ = '0';
      n++;
    }

    while ((lo % 10) == 0)
      lo /= 10;

    zp += encode64(zp, lo);
  }

  return zp - sp;
}

int
btc_amount_import(int64_t *z, const char *xp) {
  int neg = (*xp == '-');
  int64_t lo = 0;
  int64_t hi;
  int64_t x;
  int n;

  xp += neg;

  if (!decode64(&hi, &xp, 19 - BTC_PRECISION))
    return 0;

  if (*xp == '.') {
    xp++;

    n = decode64(&lo, &xp, BTC_PRECISION);

    if (n == 0)
      return 0;

    if (lo != 0) {
      while (n < BTC_PRECISION) {
        lo *= 10;
        n++;
      }
    }
  }

  if (*xp != '\0')
    return 0;

  if (hi > (BTC_MAX_MONEY / BTC_COIN))
    return 0;

  x = hi * BTC_COIN + lo;

  if (x > BTC_MAX_MONEY)
    return 0;

  if (neg)
    x = -x;

  *z = x;

  return 1;
}

double
btc_amount_to_double(int64_t x) {
  return (double)x / (double)BTC_COIN;
}

int
btc_amount_from_double(int64_t *z, double x) {
  if (x != x)
    return 0;

  if (x < -BTC_MAX_COINS || x > BTC_MAX_COINS)
    return 0;

  *z = x * (double)BTC_COIN + (x < 0.0 ? -0.5 : 0.5);

  if (*z < -BTC_MAX_MONEY || *z > BTC_MAX_MONEY)
    return 0;

  return 1;
}
