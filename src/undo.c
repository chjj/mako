/*!
 * undo.c - undo coins for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <satoshi/coins.h>
#include "impl.h"
#include "internal.h"

/*
 * Undo Coins
 */

DEFINE_SERIALIZABLE_VECTOR(btc_undo, btc_coin, SCOPE_EXTERN)
