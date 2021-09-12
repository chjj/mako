/*!
 * outvec.c - output vector for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <satoshi/tx.h>
#include <torsion/hash.h>
#include "impl.h"
#include "internal.h"

/*
 * Output Vector
 */

DEFINE_HASHABLE_VECTOR(btc_outvec, btc_output, SCOPE_EXTERN)
