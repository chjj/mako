/*!
 * rand.h - entropy sources for mako
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifndef BTC_SYS_H
#define BTC_SYS_H

#include <stddef.h>
#include <stdint.h>

/*
 * Alias
 */

#define btc_getpid btc__getpid
#define btc_sysrand btc__sysrand

/*
 * Entropy
 */

long
btc_getpid(void);

int
btc_sysrand(void *dst, size_t size);

#endif /* BTC_SYS_H */
