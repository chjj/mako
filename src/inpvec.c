/*!
 * inpvec.c - input vector for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <satoshi/tx.h>
#include <satoshi/crypto/hash.h>
#include "impl.h"
#include "internal.h"

/*
 * Input Vector
 */

DEFINE_HASHABLE_VECTOR(btc_inpvec, btc_input, SCOPE_EXTERN)
