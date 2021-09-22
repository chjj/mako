/*!
 * time.c - unix time for libsatoshi
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/time.h>
#include <io/core.h>

/*
 * Time
 */

void
btc_time_get(btc_timespec_t *ts) {
  struct timeval tv;

  if (gettimeofday(&tv, NULL) != 0)
    abort();

  ts->tv_sec = tv.tv_sec;
  ts->tv_nsec = (uint32_t)tv.tv_usec * 1000;
}
