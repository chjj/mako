/*!
 * intmap.c - integer map for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <satoshi/map.h>
#include "map.h"

/*
 * Integer Map
 */

DEFINE_UINT32_MAP(btc_intmap, void *, NULL, MAP_EXTERN)
