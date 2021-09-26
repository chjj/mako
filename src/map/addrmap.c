/*!
 * addrmap.c - network address map for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <satoshi/map.h>
#include <satoshi/netaddr.h>
#include "map.h"

/*
 * Network Address Map
 */

DEFINE_NETADDR_MAP(btc_addrmap, void *, NULL, MAP_EXTERN)
