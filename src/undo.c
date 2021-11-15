/*!
 * undo.c - undo coins for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <mako/coins.h>
#include "impl.h"
#include "internal.h"

/*
 * Undo Coins
 */

DEFINE_SERIALIZABLE_VECTOR(btc_undo, btc_coin, SCOPE_EXTERN)
