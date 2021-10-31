/*!
 * time.c - unix time for libsatoshi
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#if !defined(FD_SETSIZE) && !defined(FD_SET)
#include <sys/select.h>
#endif
#include <io/core.h>

/*
 * Time
 */

void
btc_time_get(btc_timespec_t *ts) {
  struct timeval tv;

  if (gettimeofday(&tv, NULL) != 0)
    abort(); /* LCOV_EXCL_LINE */

  ts->tv_sec = tv.tv_sec;
  ts->tv_nsec = tv.tv_usec * 1000;
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
