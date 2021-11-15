/*!
 * outmap.c - outpoint map for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <mako/map.h>
#include <mako/tx.h>
#include "map.h"

/*
 * Outpoint Map
 */

DEFINE_OUTPOINT_MAP(btc_outmap, void *, NULL, MAP_EXTERN)
