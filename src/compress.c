/*!
 * compress.c - coin compression for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <limits.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <mako/crypto/ecc.h>
#include <mako/script.h>
#include <mako/tx.h>
#include "impl.h"
#include "internal.h"

/*
 * Script Types
 */

static int
btc_script_is_p2pkh_strict(const btc_script_t *x) {
  return x->length == 25
      && x->data[0] == BTC_OP_DUP
      && x->data[1] == BTC_OP_HASH160
      && x->data[2] == 20
      && x->data[23] == BTC_OP_EQUALVERIFY
      && x->data[24] == BTC_OP_CHECKSIG;
}

static int
btc_script_is_p2sh_strict(const btc_script_t *x) {
  return btc_script_is_p2sh(x);
}

static int
btc_script_is_p2pk_strict(const btc_script_t *x) {
  if (x->length == 35) {
    return x->data[0] == 33
        && (x->data[1] == 0x02 || x->data[1] == 0x03)
        && x->data[34] == BTC_OP_CHECKSIG;
  }

  if (x->length == 67) {
    return x->data[0] == 65
        && x->data[1] == 0x04
        && x->data[66] == BTC_OP_CHECKSIG;
  }

  return 0;
}

/*
 * Script Compression
 */

size_t
btc_script_deflate(const btc_script_t *x) {
  if (btc_script_is_p2pkh_strict(x))
    return 21;

  if (btc_script_is_p2sh_strict(x))
    return 21;

  if (btc_script_is_p2pk_strict(x)) {
    const uint8_t *key = x->data + 1;

    if (key[0] < 4)
      return 33;

    if (btc_ecdsa_pubkey_verify(key, 65))
      return 33;
  }

  return btc_varint_size(x->length + 6) + x->length;
}

uint8_t *
btc_script_compress(uint8_t *zp, const btc_script_t *x) {
  if (btc_script_is_p2pkh_strict(x)) {
    zp = btc_uint8_write(zp, 0x00);
    zp = btc_raw_write(zp, x->data + 3, 20);
    return zp;
  }

  if (btc_script_is_p2sh_strict(x)) {
    zp = btc_uint8_write(zp, 0x01);
    zp = btc_raw_write(zp, x->data + 2, 20);
    return zp;
  }

  if (btc_script_is_p2pk_strict(x)) {
    const uint8_t *key = x->data + 1;

    if (key[0] < 4)
      return btc_raw_write(zp, key, 33);

    if (btc_ecdsa_pubkey_verify(key, 65)) {
      zp = btc_uint8_write(zp, key[0] | (key[64] & 1));
      zp = btc_raw_write(zp, key + 1, 32);
      return zp;
    }
  }

  zp = btc_varint_write(zp, x->length + 6);
  zp = btc_raw_write(zp, x->data, x->length);

  return zp;
}

int
btc_script_decompress(btc_script_t *z, const uint8_t **xp, size_t *xn) {
  const uint8_t *zp;
  uint64_t zn;

  if (!btc_varint_read(&zn, xp, xn))
    return 0;

  if (zn > INT_MAX)
    return 0;

  switch ((int)zn) {
    case 0x00: {
      if (!btc_zraw_read(&zp, 20, xp, xn))
        return 0;

      btc_script_set_p2pkh(z, zp);

      break;
    }

    case 0x01: {
      if (!btc_zraw_read(&zp, 20, xp, xn))
        return 0;

      btc_script_set_p2sh(z, zp);

      break;
    }

    case 0x02:
    case 0x03: {
      if (!btc_zraw_read(&zp, 32, xp, xn))
        return 0;

      btc_script_set_p2pk(z, zp - 1, 33);

      break;
    }

    case 0x04:
    case 0x05: {
      uint8_t key[65];

      key[0] = zn - 2;

      if (!btc_raw_read(key + 1, 32, xp, xn))
        return 0;

      if (!btc_ecdsa_pubkey_convert(key, key, 33, 0))
        return 0;

      btc_script_set_p2pk(z, key, 65);

      break;
    }

    default: {
      zn -= 6;

      if (!btc_zraw_read(&zp, zn, xp, xn))
        return 0;

      btc_script_set(z, zp, zn);

      break;
    }
  }

  return 1;
}

/*
 * Value Compression (from Bitcoin Core)
 */

static uint64_t
btc_value_compress(uint64_t n) {
  int e, d;

  if (n == 0)
    return 0;

  e = 0;

  while (((n % 10) == 0) && e < 9) {
    n /= 10;
    e++;
  }

  if (e < 9) {
    d = (n % 10);

    ASSERT(d >= 1 && d <= 9);

    n /= 10;

    return 1 + (n * 9 + d - 1) * 10 + e;
  }

  return 1 + (n - 1) * 10 + 9;
}

static uint64_t
btc_value_decompress(uint64_t x) {
  uint64_t n;
  int e, d;

  /* x = 0 OR x = 1 + 10 * (9 * n + d - 1) + e
           OR x = 1 + 10 * (n - 1) + 9 */
  if (x == 0)
    return 0;

  x--;

  /* x = 10 * (9 * n + d - 1) + e */
  e = x % 10;
  x /= 10;
  n = 0;

  if (e < 9) {
    /* x = 9 * n + d - 1 */
    d = (x % 9) + 1;
    x /= 9;
    /* x = n */
    n = x * 10 + d;
  } else {
    n = x + 1;
  }

  while (e) {
    n *= 10;
    e--;
  }

  return n;
}

/*
 * Output Compression
 */

size_t
btc_output_deflate(const btc_output_t *x) {
  return btc_varint_size(btc_value_compress(x->value))
       + btc_script_deflate(&x->script);
}

uint8_t *
btc_output_compress(uint8_t *zp, const btc_output_t *x) {
  zp = btc_varint_write(zp, btc_value_compress(x->value));
  zp = btc_script_compress(zp, &x->script);
  return zp;
}

int
btc_output_decompress(btc_output_t *z, const uint8_t **xp, size_t *xn) {
  uint64_t value;

  if (!btc_varint_read(&value, xp, xn))
    return 0;

  z->value = btc_value_decompress(value);

  if (!btc_script_decompress(&z->script, xp, xn))
    return 0;

  return 1;
}
