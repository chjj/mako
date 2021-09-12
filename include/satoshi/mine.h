/*!
 * mine.h - mine for libsatoshi
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef BTC_MINE_H
#define BTC_MINE_H

#include <stddef.h>
#include <stdint.h>
#include "common.h"
#include "impl.h"
#include "types.h"

/*
 * Mining / PoW
 */

BTC_EXTERN int
btc_mine(btc_header_t *hdr,
         const uint8_t *target,
         uint64_t limit,
         uint32_t (*adjtime)(void *),
         void *arg);

#endif /* BTC_MINE_H */
