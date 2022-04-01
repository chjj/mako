/*!
 * math.h - math shim for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifndef BTC_MATH_H
#define BTC_MATH_H

/*
 * Compat
 */

#undef BTC_HAVE_MATH

#ifndef __dietlibc__
#  define BTC_HAVE_MATH
#endif

/*
 * Math Shim
 */

double
btc_round(double x);

#ifdef BTC_HAVE_MATH
#  include <math.h>
#  define btc_floor floor
#  define btc_ceil ceil
#  define btc_pow pow
#  define btc_modf modf
#  define btc_ln log
#  define btc_exp exp
#else /* !BTC_HAVE_MATH */
double
btc_floor(double x);

double
btc_ceil(double x);

double
btc_pow(double x, double y);

double
btc_modf(double x, double *iptr);

double
btc_ln(double x);

double
btc_exp(double x);
#endif /* !BTC_HAVE_MATH */

#endif /* BTC_MATH_H */
