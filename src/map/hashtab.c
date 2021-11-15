/*!
 * hashtab.c - hash table for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <mako/map.h>
#include "map.h"

/*
 * Hash Table
 */

DEFINE_HASH_MAP(btc_hashtab, int64_t, -1, MAP_EXTERN)
