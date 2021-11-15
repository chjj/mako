/*!
 * inpvec.c - input vector for mako
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
 * Input Vector
 */

DEFINE_HASHABLE_VECTOR(btc_inpvec, btc_input, SCOPE_EXTERN)
