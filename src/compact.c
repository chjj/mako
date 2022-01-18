/*!
 * compact.c - compact for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdlib.h>
#include <stdint.h>
#include <mako/mpi.h>
#include <mako/util.h>
#include "internal.h"

/*
 * Compact
 */

int
btc_compact_compare(uint32_t x, uint32_t y) {
  mpz_t u, v;
  int ret;

  mpz_init_set_compact(u, x);
  mpz_init_set_compact(v, y);

  ret = mpz_cmp(u, v);

  mpz_clear(u);
  mpz_clear(v);

  return ret;
}

int
btc_compact_export(uint8_t *target, uint32_t bits) {
  int ret = 0;
  mpz_t z;

  mpz_init_set_compact(z, bits);

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

  mpz_init_import(x, target, 32, -1);

  bits = mpz_get_compact(x);

  mpz_clear(x);

  return bits;
}
