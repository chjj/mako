/*!
 * time.c - unix time for mako
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sys/types.h>
#include <sys/time.h>

#if !defined(FD_SETSIZE) && !defined(FD_SET)
#  include <sys/select.h>
#endif

#include <io/core.h>

/*
 * Compat
 */

#if defined(BTC_HAVE_CLOCK)
#  if defined(__APPLE__) && defined(__GNUC__)
#    pragma GCC diagnostic ignored "-Waddress"
#  endif
#  define BTC_REALTIME CLOCK_REALTIME
#  define BTC_MONOTONIC CLOCK_MONOTONIC
typedef clockid_t btc_clockid_t;
#else
typedef enum btc_clockid {
  BTC_REALTIME,
  BTC_MONOTONIC
} btc_clockid_t;
#endif

/*
 * Helpers
 */

static void
btc_gettimeofday(btc_timespec_t *ts) {
  struct timeval tv;

  if (gettimeofday(&tv, NULL) != 0)
    abort(); /* LCOV_EXCL_LINE */

  ts->tv_sec = tv.tv_sec;
  ts->tv_nsec = tv.tv_usec * 1000;
}

static void
btc_clock_gettime(btc_clockid_t clock_id, btc_timespec_t *res) {
#if defined(BTC_HAVE_CLOCK)
  struct timespec ts;

#ifdef __APPLE__
  if (&clock_gettime == NULL)
    goto fallback; /* LCOV_EXCL_LINE */
#endif

  if (clock_gettime(clock_id, &ts) != 0)
    goto fallback; /* LCOV_EXCL_LINE */

  res->tv_sec = ts.tv_sec;
  res->tv_nsec = ts.tv_nsec;

  return;
fallback:
  btc_gettimeofday(res); /* LCOV_EXCL_LINE */
#else
  (void)clock_id;
  btc_gettimeofday(res);
#endif
}

/*
 * Time
 */

void
btc_time_get(btc_timespec_t *ts) {
  btc_clock_gettime(BTC_REALTIME, ts);
}

int64_t
btc_time_sec(void) {
  btc_timespec_t ts;

  btc_clock_gettime(BTC_MONOTONIC, &ts);

  return ts.tv_sec;
}

int64_t
btc_time_msec(void) {
  btc_timespec_t ts;

  btc_clock_gettime(BTC_MONOTONIC, &ts);

  return (ts.tv_sec * 1000) + (ts.tv_nsec / 1000000);
}

int64_t
btc_time_usec(void) {
  btc_timespec_t ts;

  btc_clock_gettime(BTC_MONOTONIC, &ts);

  return (ts.tv_sec * 1000000) + (ts.tv_nsec / 1000);
}

int64_t
btc_time_nsec(void) {
  btc_timespec_t ts;

  btc_clock_gettime(BTC_MONOTONIC, &ts);

  return (ts.tv_sec * 1000000000) + ts.tv_nsec;
}

void
btc_time_sleep(int64_t msec) {
  struct timeval tv;
#ifdef __linux__
  int rc;
#endif

  memset(&tv, 0, sizeof(tv));

  if (msec <= 0) {
    tv.tv_usec = 1;
  } else {
    tv.tv_sec = msec / 1000;
    tv.tv_usec = (msec % 1000) * 1000;
  }

  /* Linux updates the timeval. This is one
     situation where we actually _want_ that
     behavior. */
#if defined(__linux__)
  do {
    rc = select(0, NULL, NULL, NULL, &tv);
  } while (rc == -1 && errno == EINTR);
#else
  select(0, NULL, NULL, NULL, &tv);
#endif
}
