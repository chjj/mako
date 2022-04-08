/*!
 * mac.h - macs for mako
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifndef BTC_MAC_H
#define BTC_MAC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "../common.h"

/*
 * Types
 */

struct btc_poly1305_32_s {
  uint32_t r[5];
  uint32_t h[5];
  uint32_t pad[4];
};

struct btc_poly1305_64_s {
  uint64_t r[3];
  uint64_t h[3];
  uint64_t pad[2];
};

typedef struct btc_poly1305_s {
  union {
    struct btc_poly1305_32_s u32;
    struct btc_poly1305_64_s u64;
  } state;
  uint8_t block[16];
  size_t pos;
} btc_poly1305_t;

/*
 * Poly1305
 */

BTC_EXTERN void
btc_poly1305_init(btc_poly1305_t *ctx, const uint8_t *key);

BTC_EXTERN void
btc_poly1305_update(btc_poly1305_t *ctx, const uint8_t *data, size_t len);

BTC_EXTERN void
btc_poly1305_pad(btc_poly1305_t *ctx);

BTC_EXTERN void
btc_poly1305_final(btc_poly1305_t *ctx, uint8_t *mac);

#ifdef __cplusplus
}
#endif

#endif /* BTC_MAC_H */
