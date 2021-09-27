/*!
 * outmap.c - outpoint map for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <satoshi/map.h>
#include <satoshi/tx.h>
#include "map.h"

/*
 * Outpoint Map
 */

DEFINE_OUTPOINT_MAP(btc_outmap, void *, NULL, MAP_EXTERN)
