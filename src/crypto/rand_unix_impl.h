/*!
 * rand_unix_impl.h - unix entropy gathering for mako
 * Copyright (c) 2021-2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stddef.h>

#include "rand.h"

/*
 * Environment Entropy
 */

int
btc_envrand(void *dst, size_t size) {
  (void)dst;
  (void)size;
  return 0;
}
