/*!
 * logger.c - logger for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#ifndef _WIN32
#include <unistd.h>
#endif
#include <io/core.h>
#include <base/logger.h>
#include <mako/printf.h>
#include <mako/util.h>
#include "../internal.h"

/*
 * Types
 */

struct btc_logger_s {
  enum btc_loglevel level;
  int output;
  int colors;
  FILE *stream;
};

/*
 * Constants
 */

static btc_logger_t default_logger = {
  /* .level = */ BTC_LOG_SPAM,
  /* .output = */ 1,
  /* .colors = */ 0,
  /* .stream = */ NULL
};

static const char *log_levels[] = {
  "none",
  "error",
  "warning",
  "info",
  "debug",
  "spam"
};

static const char *log_colors[] = {
  "0",
  "1;31",
  "1;33",
  "94",
  "90",
  "90"
};

/*
 * Logger
 */

btc_logger_t *
btc_logger_create(void) {
  btc_logger_t *logger = (btc_logger_t *)btc_malloc(sizeof(btc_logger_t));

  logger->level = BTC_LOG_SPAM;
  logger->output = 1;
#if defined(_WIN32)
  logger->colors = 0;
#else
  logger->colors = isatty(STDOUT_FILENO);
#endif
  logger->stream = NULL;

  return logger;
}

void
btc_logger_destroy(btc_logger_t *logger) {
  btc_free(logger);
}

void
btc_logger_set_level(btc_logger_t *logger, enum btc_loglevel level) {
  logger->level = level;
}

void
btc_logger_set_silent(btc_logger_t *logger, int silent) {
  logger->output = !silent;
}

int
btc_logger_open(btc_logger_t *logger, const char *file) {
  FILE *stream = btc_fs_fopen(file, "a");

  if (stream == NULL)
    return 0;

  logger->stream = stream;

  return 1;
}

void
btc_logger_close(btc_logger_t *logger) {
  if (logger->stream != NULL)
    fclose(logger->stream);

  logger->stream = NULL;
}

void
btc_logger_write(btc_logger_t *logger,
                 enum btc_loglevel level,
                 const char *name,
                 const char *fmt,
                 va_list ap) {
  char line[1024];

  if (logger == NULL)
    logger = &default_logger;

  if (logger->level < level)
    return;

  if (!logger->output && logger->stream == NULL)
    return;

  btc_vsnprintf(line, sizeof(line), fmt, ap);

  if (logger->output) {
    FILE *stream = stdout;

    if (level == BTC_LOG_ERROR)
      stream = stderr;

    if (logger->colors) {
      fprintf(stream, "\x1b[%sm[%s]\x1b[m (%s) %s\n",
                      log_colors[level],
                      log_levels[level],
                      name,
                      line);
    } else {
      fprintf(stream, "[%s] (%s) %s\n", log_levels[level], name, line);
    }
  }

  if (logger->stream != NULL) {
    int ch = log_levels[level][0] & ~32;
    char date[32];

    btc_snprintf(date, sizeof(date), "%D", btc_now());

    fprintf(logger->stream, "[%c:%s] (%s) %s\n", ch, date, name, line);
  }
}
