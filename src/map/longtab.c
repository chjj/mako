/*!
 * longtab.c - long integer table for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <satoshi/map.h>
#include "map.h"

/*
 * Long Integer Table
 */

DEFINE_UINT64_MAP(btc_longtab, int64_t, -1, MAP_EXTERN)
