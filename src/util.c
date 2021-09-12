/*!
 * util.c - util for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <satoshi/util.h>
#include "impl.h"
#include "internal.h"

/*
 * Mining / PoW
 */

int
btc_hash_compare(const uint8_t *x, const uint8_t *y) {
  int i;

  for (i = 32 - 1; i >= 0; i--) {
    if (x[i] != y[i])
      return (int)x[i] - (int)y[i];
  }

  return 0;
}
