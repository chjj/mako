/*!
 * hashtab.c - hash table for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <satoshi/map.h>
#include "map.h"

/*
 * Hash Table
 */

DEFINE_HASH_MAP(btc_hashtab, int64_t, -1, MAP_EXTERN)
