/*!
 * printf.h - printf for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef BTC_PRINTF_H
#define BTC_PRINTF_H

#include <stdarg.h>
#include <stdio.h>

/*
 * Print
 */

int
btc_printf(const char *fmt, ...);

int
btc_vprintf(const char *fmt, va_list ap);

int
btc_fprintf(FILE *stream, const char *fmt, ...);

int
btc_vfprintf(FILE *stream, const char *fmt, va_list ap);

int
btc_sprintf(char *str, const char *fmt, ...);

int
btc_vsprintf(char *str, const char *fmt, va_list ap);

int
btc_snprintf(char *str, size_t size, const char *fmt, ...);

int
btc_vsnprintf(char *str, size_t size, const char *fmt, va_list ap);

#endif /* BTC_PRINTF_H */
