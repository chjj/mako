/*!
 * time.c - windows time for mako
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 *
 * Parts of this software are based on libuv/libuv:
 *   Copyright (c) 2015-2020, libuv project contributors (MIT License).
 *   https://github.com/libuv/libuv
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <io/core.h>

/*
 * Globals
 */

static btc_once_t btc_freq_guard = BTC_ONCE_INIT;
static double btc_freq_inv = 1.0;

/*
 * Helpers
 */

static void
btc_time_qpf(void) {
  LARGE_INTEGER freq;

  if (!QueryPerformanceFrequency(&freq))
    abort(); /* LCOV_EXCL_LINE */

  if (freq.QuadPart == 0)
    abort(); /* LCOV_EXCL_LINE */

  btc_freq_inv = 1.0 / (double)freq.QuadPart;
}

static int64_t
btc_time_qpc(double scale) {
  LARGE_INTEGER ctr;

  btc_once(&btc_freq_guard, btc_time_qpf);

  if (!QueryPerformanceCounter(&ctr))
    abort(); /* LCOV_EXCL_LINE */

  return ((double)ctr.QuadPart * btc_freq_inv) * scale;
}

/*
 * Time
 */

void
btc_time_get(btc_timespec_t *ts) {
  /* We borrow some more code from libuv[1] in order
   * to convert NT time to unix time. Note that the
   * libuv code was originally based on postgres[2].
   *
   * NT's epoch[3] begins on January 1st, 1601: 369
   * years earlier than the unix epoch.
   *
   * [1] https://github.com/libuv/libuv/blob/7967448/src/win/util.c#L1942
   * [2] https://doxygen.postgresql.org/gettimeofday_8c_source.html
   * [3] https://en.wikipedia.org/wiki/Epoch_(computing)
   */
  static const uint64_t epoch = UINT64_C(116444736000000000);
  ULARGE_INTEGER ul;
  FILETIME ft;

  GetSystemTimeAsFileTime(&ft);

  ul.LowPart = ft.dwLowDateTime;
  ul.HighPart = ft.dwHighDateTime;

  ts->tv_sec = (ul.QuadPart - epoch) / 10000000;
  ts->tv_nsec = ((ul.QuadPart - epoch) % 10000000) * 100;
}

int64_t
btc_time_sec(void) {
  return btc_time_qpc(1.0);
}

int64_t
btc_time_msec(void) {
  return btc_time_qpc(1000.0);
}

int64_t
btc_time_usec(void) {
  return btc_time_qpc(1000000.0);
}

int64_t
btc_time_nsec(void) {
  return btc_time_qpc(1000000000.0);
}

void
btc_time_sleep(int64_t msec) {
  if (msec < 0)
    msec = 0;

  Sleep((DWORD)msec);
}
