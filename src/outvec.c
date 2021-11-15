/*!
 * outvec.c - output vector for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <mako/tx.h>
#include <mako/crypto/hash.h>
#include "impl.h"
#include "internal.h"

/*
 * Output Vector
 */

DEFINE_HASHABLE_VECTOR(btc_outvec, btc_output, SCOPE_EXTERN)
