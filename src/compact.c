/*!
 * compact.c - compact for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <satoshi/coins.h>
#include <satoshi/mpi.h>
#include "impl.h"
#include "internal.h"

/*
 * Compact
 */

int
btc_compact_export(uint8_t *target, uint32_t bits) {
  int ret = 0;
  mpz_t z;

  mpz_init(z);
  mpz_set_compact(z, bits);

  if (mpz_sgn(z) <= 0)
    goto fail;

  if (mpz_bitlen(z) > 256)
    goto fail;

  mpz_export(target, z, 32, -1);
  ret = 1;
fail:
  mpz_clear(z);
  return ret;
}

uint32_t
btc_compact_import(const uint8_t *target) {
  uint32_t bits;
  mpz_t x;

  mpz_init(x);
  mpz_import(x, target, 32, -1);

  bits = mpz_get_compact(x);

  mpz_clear(x);

  return bits;
}
