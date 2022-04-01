/*!
 * math.c - math shim for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdint.h>
#include <stdlib.h>
#include "math.h"

/*
 * Math Shim
 *
 * The code below isn't perfect, but it
 * should be good enough for our uses.
 */

double
btc_round(double x) {
  if (x < 0.0)
    return -(double)((uint64_t)(-x + 0.5));

  return (double)((uint64_t)(x + 0.5));
}

#ifndef BTC_HAVE_MATH
double
btc_floor(double x) {
  if (x < 0.0)
    return -btc_ceil(-x);

  return (double)((uint64_t)x);
}

double
btc_ceil(double x) {
  uint64_t hi;
  double lo;

  if (x < 0.0)
    return -btc_floor(-x);

  hi = (uint64_t)x;
  lo = x - (double)hi;

  return (double)(hi + (lo != 0.0));
}

double
btc_pow(double x, double y) {
  double z = 1.0;
  uint64_t e;

  if (y < 0.0) {
    if (x == 0.0)
      return 0.0;

    x = 1.0 / x;
    y = -y;
  }

  e = (uint64_t)y;

  while (e > 0) {
    if (e & 1)
      z *= x;

    x *= x;
    e >>= 1;
  }

  return z;
}

double
btc_modf(double x, double *iptr) {
  *iptr = (double)((int64_t)x);
  return x - *iptr;
}

double
btc_ln(double x) {
  unsigned int key;

  if (x == 0.00000001) return -18.4206807439523672;
  if (x == 0.0000001) return -16.1180956509583204;
  if (x == 0.000001) return -13.8155105579642736;
  if (x == 0.00001) return -11.5129254649702286;
  if (x == 0.0001) return -9.2103403719761818;
  if (x == 0.001) return -6.9077552789821368;
  if (x == 0.01) return -4.6051701859880909;
  if (x == 0.1) return -2.3025850929940455;
  if (x == 0.5) return -0.6931471805599453;

  if (x < 0.0 || x != x)
    abort(); /* LCOV_EXCL_LINE */

  key = (unsigned int)(x * 1000.0);

  switch (key) {
    case 482: /* 0.4820525320768788 */
      return -0.7297021831588990;
    case 491: /* 0.4919781953086979 */
      return -0.7093208819501780;
    case 494: /* 0.4945203178808760 */
      return -0.7041670410367015;
    case 498: /* 0.4988127663727278 */
      return -0.6955244713323139;
    case 503: /* 0.5038052396997097 */
      return -0.6855655147610021;
    case 507: /* 0.5076117368293260 */
      return -0.6780384212080245;
    case 535: /* 0.5358411166387220 */
      return -0.6239175860351555;
  }

  abort(); /* LCOV_EXCL_LINE */
  return 0.0; /* LCOV_EXCL_LINE */
}

double
btc_exp(double x) {
  unsigned int key;

  if (x >= 0.0 || x != x)
    abort(); /* LCOV_EXCL_LINE */

  key = (unsigned int)(-x * 1000.0);

  switch (key) {
    case 657: /* -0.6578814551411558 */
      return 0.5179474679231212;
    case 677: /* -0.6772309097041311 */
      return 0.5080218046913021;
    case 682: /* -0.6822474349611988 */
      return 0.5054796821191240;
    case 690: /* -0.6907755278982137 */
      return 0.5011872336272722;
    case 700: /* -0.7007867674329704 */
      return 0.4961947603002903;
    case 708: /* -0.7084877209212448 */
      return 0.4923882631706740;
    case 767: /* -0.7675283643313485 */
      return 0.4641588833612779;
  }

  abort(); /* LCOV_EXCL_LINE */
  return 0.0; /* LCOV_EXCL_LINE */
}
#endif /* !BTC_HAVE_MATH */
