/*!
 * logger.h - logger for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifndef BTC_LOGGER_H
#define BTC_LOGGER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdarg.h>
#include <stddef.h>
#include "types.h"
#include "../mako/common.h"

/*
 * Constants
 */

enum btc_loglevel {
  BTC_LOG_NONE = 0,
  BTC_LOG_ERROR = 1,
  BTC_LOG_WARNING = 2,
  BTC_LOG_INFO = 3,
  BTC_LOG_DEBUG = 4,
  BTC_LOG_SPAM = 5
};

/*
 * Macros
 */

#define BTC_DEFINE_LOGFN(prefix, suffix, type, level, name) \
BTC_UNUSED static void                                      \
prefix##_##suffix (type *obj, const char *fmt, ...) {       \
  va_list ap;                                               \
  va_start(ap, fmt);                                        \
  btc_logger_write(obj->logger, level, name, fmt, ap);      \
  va_end(ap);                                               \
}

#define BTC_DEFINE_LOGGER(prefix, type, name)                 \
  BTC_DEFINE_LOGFN(prefix, error, type, BTC_LOG_ERROR, name)  \
  BTC_DEFINE_LOGFN(prefix, warn, type, BTC_LOG_WARNING, name) \
  BTC_DEFINE_LOGFN(prefix, info, type, BTC_LOG_INFO, name)    \
  BTC_DEFINE_LOGFN(prefix, debug, type, BTC_LOG_DEBUG, name)  \
  BTC_DEFINE_LOGFN(prefix, spam, type, BTC_LOG_SPAM, name)

/*
 * Logger
 */

BTC_EXTERN btc_logger_t *
btc_logger_create(void);

BTC_EXTERN void
btc_logger_destroy(btc_logger_t *logger);

BTC_EXTERN void
btc_logger_set_level(btc_logger_t *logger, enum btc_loglevel level);

BTC_EXTERN void
btc_logger_set_silent(btc_logger_t *logger, int silent);

BTC_EXTERN int
btc_logger_open(btc_logger_t *logger, const char *file);

BTC_EXTERN void
btc_logger_close(btc_logger_t *logger);

BTC_EXTERN void
btc_logger_write(btc_logger_t *logger,
                 enum btc_loglevel level,
                 const char *name,
                 const char *fmt,
                 va_list ap);

#ifdef __cplusplus
}
#endif

#endif /* BTC_LOGGER_H */
