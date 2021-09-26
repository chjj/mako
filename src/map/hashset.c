/*!
 * hashset.c - hash set for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <satoshi/map.h>
#include "map.h"

/*
 * Hash Set
 */

DEFINE_HASH_SET(btc_hashset, MAP_EXTERN)
