/*!
 * types.h - node types for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifndef BTC_BASE_TYPES_H
#define BTC_BASE_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "../mako/types.h"

/*
 * Types
 */

struct btc_network_s;

typedef struct btc_addrman_s btc_addrman_t;
typedef struct btc_conf_s btc_conf_t;
typedef struct btc_logger_s btc_logger_t;

typedef struct btc_timedata_s {
  int64_t samples[200];
  size_t length;
  int64_t offset;
  int checked;
} btc_timedata_t;

#ifdef __cplusplus
}
#endif

#endif /* BTC_BASE_TYPES_H */
