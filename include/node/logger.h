/*!
 * logger.h - logger for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef BTC_LOGGER_H
#define BTC_LOGGER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdarg.h>
#include <stddef.h>
#include "../satoshi/common.h"

/*
 * Types
 */

typedef struct btc_logger_s btc_logger_t;

/*
 * Logger
 */

BTC_EXTERN btc_logger_t *
btc_logger_create(void);

BTC_EXTERN void
btc_logger_destroy(btc_logger_t *logger);

BTC_EXTERN void
btc_logger_set_silent(btc_logger_t *logger, int silent);

BTC_EXTERN int
btc_logger_open(btc_logger_t *logger, const char *file);

BTC_EXTERN void
btc_logger_close(btc_logger_t *logger);

BTC_EXTERN void
btc_logger_write(btc_logger_t *logger,
                 const char *pre,
                 const char *fmt,
                 va_list ap);

#ifdef __cplusplus
}
#endif

#endif /* BTC_LOGGER_H */
