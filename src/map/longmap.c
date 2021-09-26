/*!
 * longmap.c - long integer map for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <satoshi/map.h>
#include "map.h"

/*
 * Long Integer Map
 */

DEFINE_UINT64_MAP(btc_longmap, void *, NULL, MAP_EXTERN)
