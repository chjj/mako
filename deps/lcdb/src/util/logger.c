/*!
 * logger.c - logger for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on google/leveldb:
 *   Copyright (c) 2011, The LevelDB Authors. All rights reserved.
 *   https://github.com/google/leveldb
 *
 * See LICENSE for more information.
 */

#undef HAVE_GETTID

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#  include <windows.h>
#elif defined(__linux__)
#  if !defined(__NEWLIB__) && !defined(__dietlibc__)
#    include <sys/types.h>
#    include <sys/syscall.h>
#    ifdef __NR_gettid
#      define HAVE_GETTID
#    endif
#  endif
#  include <unistd.h>
#else
#  include <unistd.h>
#endif

#if !defined(_WIN32) && defined(LDB_PTHREAD)
#  include <pthread.h>
#endif

#include "env.h"
#include "internal.h"

/*
 * Types
 */

struct ldb_logger_s {
  FILE *stream;
};

/*
 * Helpers
 */

static int
ldb_date(char *zp, int64_t x) {
  /* https://stackoverflow.com/a/42936293 */
  /* https://howardhinnant.github.io/date_algorithms.html#civil_from_days */
  int64_t xx = x / 1000000;
  int zz = (xx / 86400) + 719468;
  int era = (zz >= 0 ? zz : zz - 146096) / 146097;
  unsigned int doe = (unsigned int)(zz - era * 146097);
  unsigned int yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
  int y = (int)yoe + era * 400;
  unsigned int doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
  unsigned int mp = (5 * doy + 2) / 153;
  unsigned int d = doy - (153 * mp + 2) / 5 + 1;
  unsigned int m = mp < 10 ? mp + 3 : mp - 9;
  unsigned int hr = (xx / 3600) % 24;
  unsigned int min = (xx / 60) % 60;
  unsigned int sec = xx % 60;
  unsigned int usec = x % 1000000;

  y += (m <= 2);

  return sprintf(zp, "%.4u/%.2u/%.2u-%.2u:%.2u:%.2u.%.6u",
                     y, m, d, hr, min, sec, usec);
}

/*
 * Logger
 */

ldb_logger_t *
ldb_logger_create(FILE *stream);

ldb_logger_t *
ldb_logger_create(FILE *stream) {
  ldb_logger_t *logger = ldb_malloc(sizeof(ldb_logger_t));
  logger->stream = stream;
  return logger;
}

void
ldb_logger_destroy(ldb_logger_t *logger) {
  if (logger != NULL) {
    if (logger->stream != NULL)
      fclose(logger->stream);

    ldb_free(logger);
  }
}

void
ldb_log(ldb_logger_t *logger, const char *fmt, ...) {
  unsigned long tid = 0;
  char date[64];
  va_list ap;

  va_start(ap, fmt);

  if (logger != NULL && logger->stream != NULL) {
    ldb_date(date, ldb_now_usec());

#if defined(_WIN32)
    tid = GetCurrentThreadId();
#elif defined(HAVE_GETTID)
    tid = syscall(__NR_gettid);
#elif defined(LDB_PTHREAD)
    {
      pthread_t thread = pthread_self();

      memcpy(&tid, &thread, LDB_MIN(sizeof(tid), sizeof(thread)));
    }
#elif !defined(__wasi__)
    tid = getpid();
#endif

    fprintf(logger->stream, "%s %lu ", date, tid);

    vfprintf(logger->stream, fmt, ap);

    fputc('\n', logger->stream);

    fflush(logger->stream);
  }

  va_end(ap);
}
