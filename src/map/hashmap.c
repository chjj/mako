/*!
 * hashmap.c - hash map for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <satoshi/map.h>
#include "map.h"

/*
 * Hash Map
 */

DEFINE_HASH_MAP(btc_hashmap, void *, NULL, MAP_EXTERN)
