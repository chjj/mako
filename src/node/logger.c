/*!
 * logger.c - logger for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <node/logger.h>
#include "printf.h"
#include "../internal.h"

/*
 * Types
 */

struct btc_logger_s {
  FILE *stream;
  int silent;
};

/*
 * Logger
 */

struct btc_logger_s *
btc_logger_create(void) {
  struct btc_logger_s *log =
    (struct btc_logger_s *)btc_malloc(sizeof(struct btc_logger_s));

  log->stream = NULL;
  log->silent = 0;

  return log;
}

void
btc_logger_destroy(struct btc_logger_s *log) {
  btc_free(log);
}

void
btc_logger_set_silent(struct btc_logger_s *log, int silent) {
  log->silent = silent;
}

int
btc_logger_open(struct btc_logger_s *log, const char *file) {
  FILE *stream = fopen(file, "a");

  if (stream == NULL)
    return 0;

  log->stream = stream;

  return 1;
}

void
btc_logger_close(struct btc_logger_s *log) {
  fclose(log->stream);
  log->stream = NULL;
}

void
btc_logger_write(struct btc_logger_s *log,
                 const char *pre,
                 const char *fmt,
                 va_list ap) {
  char tmp[1024];
  int len = 0;

  if (log == NULL || log->silent == 0 || log->stream != NULL) {
    int rem = sizeof(tmp) - 1;
    char *ptr = tmp;

    if (pre != NULL) {
      len = btc_snprintf(tmp, rem, "[%s] ", pre);

      CHECK(len >= 0 && len < rem);

      ptr += len;
      rem -= len;
    }

    len = btc_vsnprintf(ptr, rem, fmt, ap);

    CHECK(len >= 0);

    if (len >= rem)
      len = rem - 1;

    ptr += len;

    *ptr++ = '\n';
    *ptr++ = '\0';

    len = (ptr - tmp) - 1;
  }

  if (log == NULL || log->silent == 0)
    fwrite(tmp, 1, len, stdout);

  if (log != NULL && log->stream != NULL)
    fwrite(tmp, 1, len, log->stream);
}
