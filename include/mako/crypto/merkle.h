/*!
 * ecc.h - ecc for mako
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifndef BTC_MERKLE_H
#define BTC_MERKLE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "../common.h"

/*
 * Merkle
 */

BTC_EXTERN int
btc_merkle_root(uint8_t *root, uint8_t *nodes, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* BTC_MERKLE_H */
