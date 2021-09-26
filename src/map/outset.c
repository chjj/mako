/*!
 * outset.c - outpoint set for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <satoshi/map.h>
#include <satoshi/tx.h>
#include "map.h"

/*
 * Outpoint Set
 */

DEFINE_OUTPOINT_SET(btc_outset, MAP_EXTERN)
