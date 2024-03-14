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

#include <assert.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "env.h"
#include "internal.h"
#include "port.h"

/*
 * Types
 */

struct ldb_logger_s {
  void *state;
  void (*logv)(void *, const char *, va_list);
  void (*destroy)(void *);
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
 * Default Logger
 */

static void
stream_log(void *state, const char *fmt, va_list ap) {
  ldb_tid_t thread = ldb_thread_self();
  unsigned long tid = 0;
  FILE *stream = state;
  char date[64];

  ldb_date(date, ldb_now_usec());

  memcpy(&tid, &thread, LDB_MIN(sizeof(tid), sizeof(thread)));

  fprintf(stream, "%s %lu ", date, tid);

  vfprintf(stream, fmt, ap);

  fputc('\n', stream);

  fflush(stream);
}

static void
stream_close(void *state) {
  fclose(state);
}

/*
 * Logger
 */

ldb_logger_t *
ldb_logger_create(void (*logv)(void *, const char *, va_list), void *state) {
  ldb_logger_t *logger = ldb_malloc(sizeof(ldb_logger_t));

  logger->state = state;
  logger->logv = logv;
  logger->destroy = NULL;

  return logger;
}

void
ldb_logger_destroy(ldb_logger_t *logger) {
  if (logger != NULL) {
    if (logger->destroy != NULL)
      logger->destroy(logger->state);

    ldb_free(logger);
  }
}

void
ldb_log(ldb_logger_t *logger, const char *fmt, ...) {
  va_list ap;

  va_start(ap, fmt);

  if (logger != NULL && logger->logv != NULL)
    logger->logv(logger->state, fmt, ap);

  va_end(ap);
}

ldb_logger_t *
ldb_logger_fopen(FILE *stream) {
  ldb_logger_t *logger = ldb_malloc(sizeof(ldb_logger_t));

  assert(stream != NULL);

  logger->state = stream;
  logger->logv = stream_log;
  logger->destroy = stream_close;

  return logger;
}
