/*!
 * outset.c - outpoint set for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <mako/map.h>
#include <mako/tx.h>
#include "map.h"

/*
 * Outpoint Set
 */

DEFINE_OUTPOINT_SET(btc_outset, MAP_EXTERN)
