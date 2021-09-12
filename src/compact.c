/*!
 * compact.c - compact for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <satoshi/coins.h>
#include <torsion/mpi.h>
#include "impl.h"
#include "internal.h"

/*
 * Compact
 */

static void
mpz_set_compact(mpz_t z, uint32_t bits) {
  uint32_t exponent, negative, mantissa;

  if (bits == 0) {
    mpz_set_ui(z, 0);
    return;
  }

  exponent = bits >> 24;
  negative = (bits >> 23) & 1;
  mantissa = bits & 0x7fffff;

  if (exponent <= 3) {
    mantissa >>= 8 * (3 - exponent);
    mpz_set_ui(z, mantissa);
  } else {
    mpz_set_ui(z, mantissa);
    mpz_mul_2exp(z, z, 8 * (exponent - 3));
  }

  if (negative)
    mpz_neg(z, z);
}

static uint32_t
mpz_get_compact(const mpz_t x) {
  uint32_t bits, exponent, negative, mantissa;
  mpz_t t;

  if (mpz_sgn(x) == 0)
    return 0;

  exponent = mpz_bytelen(x);
  negative = mpz_sgn(x) < 0;

  if (exponent <= 3) {
    mantissa = mpz_get_ui(x);
    mantissa <<= 8 * (3 - exponent);
  } else {
    mpz_init(t);
    mpz_quo_2exp(t, x, 8 * (exponent - 3));
    mantissa = mpz_get_ui(t);
    mpz_clear(t);
  }

  if (mantissa & 0x800000) {
    mantissa >>= 8;
    exponent += 1;
  }

  bits = (exponent << 24) | mantissa;

  if (negative)
    bits |= 0x800000;

  return bits;
}

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
