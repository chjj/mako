/*!
 * ecc.c - ecc for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <satoshi/crypto/ecc.h>
#include <satoshi/crypto/rand.h>
#include <satoshi/util.h>
#include "ecc.h"
#include "../internal.h"

static wei_curve_t *btc_secp256k1;

static const wei_curve_t *
btc_curve(void) {
  if (btc_secp256k1 == NULL)
    btc_secp256k1 = wei_curve_create(WEI_CURVE_SECP256K1);

  return btc_secp256k1;
}

void
btc_ecdsa_privkey_generate(uint8_t *out) {
  uint8_t entropy[32];

  btc_getrandom(entropy, 32);

  ecdsa_privkey_generate(btc_curve(), out, entropy);

  btc_memzero(entropy, 32);
}

int
btc_ecdsa_privkey_verify(const uint8_t *priv) {
  return ecdsa_privkey_verify(btc_curve(), priv);
}

int
btc_ecdsa_privkey_tweak_add(uint8_t *out,
                            const uint8_t *priv,
                            const uint8_t *tweak) {
  return ecdsa_privkey_tweak_add(btc_curve(), out, priv, tweak);
}

int
btc_ecdsa_pubkey_create(uint8_t *pub,
                        const uint8_t *priv,
                        int compact) {
  return ecdsa_pubkey_create(btc_curve(), pub, NULL, priv, compact);
}

int
btc_ecdsa_pubkey_convert(uint8_t *out,
                         const uint8_t *pub,
                         size_t pub_len,
                         int compact) {
  return ecdsa_pubkey_convert(btc_curve(), out, NULL, pub, pub_len, compact);
}

int
btc_ecdsa_pubkey_verify(const uint8_t *pub, size_t pub_len) {
  return ecdsa_pubkey_verify(btc_curve(), pub, pub_len);
}

int
btc_ecdsa_pubkey_tweak_add(uint8_t *out,
                           const uint8_t *pub,
                           size_t pub_len,
                           const uint8_t *tweak,
                           int compact) {
  return ecdsa_pubkey_tweak_add(btc_curve(), out, NULL,
                                             pub, pub_len,
                                             tweak, compact);
}

int
btc_ecdsa_is_low_der(const uint8_t *der, size_t der_len) {
  const wei_curve_t *ec = btc_curve();
  uint8_t sig[64];

  if (!ecdsa_sig_import(ec, sig, der, der_len))
    return 0;

  return ecdsa_is_low_s(ec, sig);
}

int
btc_ecdsa_sign(uint8_t *der,
               size_t *der_len,
               const uint8_t *msg,
               const uint8_t *priv) {
  const wei_curve_t *ec = btc_curve();
  uint8_t sig[64];
  int ret = 1;

  ret &= ecdsa_sign(ec, sig, NULL, msg, 32, priv);
  ret &= ecdsa_sig_export(ec, der, der_len, sig);

  return ret;
}

int
btc_ecdsa_verify(const uint8_t *msg,
                 const uint8_t *der,
                 size_t der_len,
                 const uint8_t *pub,
                 size_t pub_len) {
  const wei_curve_t *ec = btc_curve();
  uint8_t sig[64];

  if (!ecdsa_sig_import(ec, sig, der, der_len))
    return 0;

  return ecdsa_verify(ec, msg, 32, sig, pub, pub_len);
}

int
btc_ecdsa_checksig(const uint8_t *msg,
                   const uint8_t *der,
                   size_t der_len,
                   const uint8_t *pub,
                   size_t pub_len) {
  const wei_curve_t *ec = btc_curve();
  uint8_t sig[64];

  if (!ecdsa_sig_import_lax(ec, sig, der, der_len))
    return 0;

  if (!ecdsa_sig_normalize(ec, sig, sig))
    return 0;

  return ecdsa_verify(ec, msg, 32, sig, pub, pub_len);
}

void
btc_bip340_privkey_generate(uint8_t *out, const uint8_t *entropy) {
  bip340_privkey_generate(btc_curve(), out, entropy);
}

int
btc_bip340_privkey_verify(const uint8_t *priv) {
  return bip340_privkey_verify(btc_curve(), priv);
}

int
btc_bip340_privkey_tweak_add(uint8_t *out,
                             const uint8_t *priv,
                             const uint8_t *tweak) {
  return bip340_privkey_tweak_add(btc_curve(), out, priv, tweak);
}

int
btc_bip340_pubkey_create(uint8_t *pub, const uint8_t *priv) {
  return bip340_pubkey_create(btc_curve(), pub, priv);
}

int
btc_bip340_pubkey_verify(const uint8_t *pub) {
  return bip340_pubkey_verify(btc_curve(), pub);
}

int
btc_bip340_pubkey_tweak_add(uint8_t *out,
                            int *negated,
                            const uint8_t *pub,
                            const uint8_t *tweak) {
  return bip340_pubkey_tweak_add(btc_curve(), out, negated, pub, tweak);
}

int
btc_bip340_pubkey_tweak_add_check(const uint8_t *pub,
                                  const uint8_t *tweak,
                                  const uint8_t *expect,
                                  int negated) {
  return bip340_pubkey_tweak_add_check(btc_curve(),
                                       pub,
                                       tweak,
                                       expect,
                                       negated);
}

int
btc_bip340_sign(uint8_t *sig, const uint8_t *msg, const uint8_t *priv) {
  uint8_t aux[32];
  int ret;

  btc_getrandom(aux, 32);

  ret = bip340_sign(btc_curve(), sig, msg, 32, priv, aux);

  btc_memzero(aux, 32);

  return ret;
}

int
btc_bip340_verify(const uint8_t *msg, const uint8_t *sig, const uint8_t *pub) {
  return bip340_verify(btc_curve(), msg, 32, sig, pub);
}
