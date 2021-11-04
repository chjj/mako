/*!
 * regtest.c - regtest for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stddef.h>
#include <stdint.h>
#include <satoshi/network.h>
#include "internal.h"

const btc_network_t *btc_regtest = NULL;
