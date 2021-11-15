/*!
 * longtab.c - long integer table for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <mako/map.h>
#include "map.h"

/*
 * Long Integer Table
 */

DEFINE_UINT64_MAP(btc_longtab, int64_t, -1, MAP_EXTERN)
