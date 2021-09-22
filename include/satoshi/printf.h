/*!
 * printf.h - printf for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef BTC_PRINTF_H
#define BTC_PRINTF_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdarg.h>
#include <stdio.h>
#include "common.h"

/*
 * Print
 */

BTC_EXTERN int
btc_printf(const char *fmt, ...);

BTC_EXTERN int
btc_vprintf(const char *fmt, va_list ap);

BTC_EXTERN int
btc_fprintf(FILE *stream, const char *fmt, ...);

BTC_EXTERN int
btc_vfprintf(FILE *stream, const char *fmt, va_list ap);

BTC_EXTERN int
btc_sprintf(char *str, const char *fmt, ...);

BTC_EXTERN int
btc_vsprintf(char *str, const char *fmt, va_list ap);

BTC_EXTERN int
btc_snprintf(char *str, size_t size, const char *fmt, ...);

BTC_EXTERN int
btc_vsnprintf(char *str, size_t size, const char *fmt, va_list ap);

#ifdef __cplusplus
}
#endif

#endif /* BTC_PRINTF_H */
