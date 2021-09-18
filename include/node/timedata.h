/*!
 * timedata.h - timedata for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef BTC_TIMEDATA_H
#define BTC_TIMEDATA_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "../satoshi/common.h"
#include "../satoshi/impl.h"

/*
 * Types
 */

typedef struct btc_timedata_s {
  int64_t samples[200];
  size_t length;
  int64_t offset;
  int checked;
} btc_timedata_t;

/*
 * Time Data
 */

BTC_DEFINE_OBJECT(btc_timedata, BTC_EXTERN)

BTC_EXTERN void
btc_timedata_init(btc_timedata_t *td);

BTC_EXTERN void
btc_timedata_clear(btc_timedata_t *td);

BTC_EXTERN void
btc_timedata_copy(btc_timedata_t *z, const btc_timedata_t *x);

BTC_EXTERN int
btc_timedata_add(btc_timedata_t *td, int64_t ts);

BTC_EXTERN int64_t
btc_timedata_now(const btc_timedata_t *td);

BTC_EXTERN int64_t
btc_timedata_adjust(const btc_timedata_t *td, int64_t ts);

BTC_EXTERN int64_t
btc_timedata_local(const btc_timedata_t *td, int64_t ts);

#ifdef __cplusplus
}
#endif

#endif /* BTC_TIMEDATA_H */
