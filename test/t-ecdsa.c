/*!
 * t-ecdsa.c - ecdsa test for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stddef.h>
#include <string.h>
#include <satoshi/crypto/drbg.h>
#include <satoshi/crypto/ecc.h>
#include <satoshi/util.h>
#include "data/ecdsa_vectors.h"
#include "tests.h"

static void
test_ecdsa_vectors(void) {
  unsigned char priv[32];
  unsigned char pub[65];
  unsigned char tweak[32];
  unsigned char privadd[32];
  unsigned char privmul[32];
  unsigned char privneg[32];
  unsigned char privinv[32];
  unsigned char pubadd[65];
  unsigned char pubmul[65];
  unsigned char pubneg[65];
  unsigned char pubdbl[65];
  unsigned char pubconv[65];
  unsigned char pubhybrid[65];
  unsigned char msg[128];
  unsigned char sig[64];
  unsigned char der[73];
  unsigned char other[32];
  unsigned char secret[65];
  unsigned char tweakneg[32];
  unsigned char tweakinv[32];
  unsigned char out[73];
  const unsigned char *pubs[3];
  size_t publens[3];
  unsigned int flag;
  unsigned int i;

  for (i = 0; i < lengthof(ecdsa_vectors); i++) {
    unsigned int param = ecdsa_vectors[i].param;
    size_t msg_len = sizeof(msg);
    size_t der_len = sizeof(der);
    size_t len;

    hex_parse(priv, 32, ecdsa_vectors[i].priv);
    hex_parse(pub, 33, ecdsa_vectors[i].pub);
    hex_parse(tweak, 32, ecdsa_vectors[i].tweak);
    hex_parse(privadd, 32, ecdsa_vectors[i].privadd);
    hex_parse(privmul, 32, ecdsa_vectors[i].privmul);
    hex_parse(privneg, 32, ecdsa_vectors[i].privneg);
    hex_parse(privinv, 32, ecdsa_vectors[i].privinv);
    hex_parse(pubadd, 33, ecdsa_vectors[i].pubadd);
    hex_parse(pubmul, 33, ecdsa_vectors[i].pubmul);
    hex_parse(pubneg, 33, ecdsa_vectors[i].pubneg);
    hex_parse(pubdbl, 33, ecdsa_vectors[i].pubdbl);
    hex_parse(pubconv, 65, ecdsa_vectors[i].pubconv);
    hex_parse(pubhybrid, 65, ecdsa_vectors[i].pubhybrid);
    hex_decode(msg, &msg_len, ecdsa_vectors[i].msg);
    hex_parse(sig, 64, ecdsa_vectors[i].sig);
    hex_decode(der, &der_len, ecdsa_vectors[i].der);
    hex_parse(other, 32, ecdsa_vectors[i].other);
    hex_parse(secret, 33, ecdsa_vectors[i].secret);

    ASSERT(btc_ecdsa_privkey_verify(priv));
    ASSERT(btc_ecdsa_pubkey_verify(pub, 33));
    ASSERT(btc_ecdsa_pubkey_verify(pubconv, 65));
    ASSERT(btc_ecdsa_pubkey_verify(pubhybrid, 65));

    ASSERT(btc_ecdsa_privkey_negate(tweakneg, tweak));
    ASSERT(btc_ecdsa_privkey_invert(tweakinv, tweak));

    ASSERT(btc_ecdsa_pubkey_create(out, priv, 1));
    ASSERT(memcmp(out, pub, 33) == 0);

    ASSERT(btc_ecdsa_privkey_tweak_add(out, priv, tweak));
    ASSERT(memcmp(out, privadd, 32) == 0);

    ASSERT(btc_ecdsa_privkey_tweak_add(out, out, tweakneg));
    ASSERT(memcmp(out, priv, 32) == 0);

    ASSERT(btc_ecdsa_privkey_tweak_mul(out, priv, tweak));
    ASSERT(memcmp(out, privmul, 32) == 0);

    ASSERT(btc_ecdsa_privkey_tweak_mul(out, out, tweakinv));
    ASSERT(memcmp(out, priv, 32) == 0);

    ASSERT(btc_ecdsa_privkey_negate(out, priv));
    ASSERT(memcmp(out, privneg, 32) == 0);

    ASSERT(btc_ecdsa_privkey_invert(out, priv));
    ASSERT(memcmp(out, privinv, 32) == 0);

    ASSERT(btc_ecdsa_pubkey_tweak_add(out, pub, 33, tweak, 1));
    ASSERT(memcmp(out, pubadd, 33) == 0);

    ASSERT(btc_ecdsa_pubkey_tweak_add(out, pubadd, 33, tweakneg, 1));
    ASSERT(memcmp(out, pub, 33) == 0);

    ASSERT(btc_ecdsa_pubkey_tweak_mul(out, pub, 33, tweak, 1));
    ASSERT(memcmp(out, pubmul, 33) == 0);

    ASSERT(btc_ecdsa_pubkey_tweak_mul(out, pubmul, 33, tweakinv, 1));
    ASSERT(memcmp(out, pub, 33) == 0);

    ASSERT(btc_ecdsa_pubkey_negate(out, pub, 33, 1));
    ASSERT(memcmp(out, pubneg, 33) == 0);

    pubs[0] = pub;
    pubs[1] = pub;

    publens[0] = 33;
    publens[1] = 33;

    ASSERT(btc_ecdsa_pubkey_combine(out, pubs, publens, 2, 1));
    ASSERT(memcmp(out, pubdbl, 33) == 0);

    pubs[0] = pubdbl;
    pubs[1] = pubneg;

    publens[0] = 33;
    publens[1] = 33;

    ASSERT(btc_ecdsa_pubkey_combine(out, pubs, publens, 2, 1));
    ASSERT(memcmp(out, pub, 33) == 0);

    pubs[0] = pub;
    pubs[1] = pubneg;
    pubs[2] = pubconv;

    publens[0] = 33;
    publens[1] = 33;
    publens[2] = 65;

    ASSERT(btc_ecdsa_pubkey_combine(out, pubs, publens, 3, 1));
    ASSERT(memcmp(out, pub, 33) == 0);

    ASSERT(!btc_ecdsa_pubkey_combine(out, pubs, publens, 2, 1));

    ASSERT(btc_ecdsa_pubkey_create(out, priv, 0));
    ASSERT(memcmp(out, pubconv, 65) == 0);

    ASSERT(btc_ecdsa_pubkey_convert(out, pub, 33, 0));
    ASSERT(memcmp(out, pubconv, 65) == 0);

    ASSERT(btc_ecdsa_pubkey_convert(out, pubconv, 65, 1));
    ASSERT(memcmp(out, pub, 33) == 0);

    ASSERT(btc_ecdsa_is_low_s(sig));

    ASSERT(btc_ecdsa_sig_export(out, &len, sig));
    ASSERT(len == der_len);
    ASSERT(memcmp(out, der, der_len) == 0);

    ASSERT(btc_ecdsa_sig_import(out, der, der_len));
    ASSERT(memcmp(out, sig, 64) == 0);

    ASSERT(btc_ecdsa_recover(out, msg, msg_len, sig, param, 1));
    ASSERT(memcmp(out, pub, 33) == 0);

    ASSERT(btc_ecdsa_recover(out, msg, msg_len, sig, param, 0));
    ASSERT(memcmp(out, pubconv, 65) == 0);

    ASSERT(btc_ecdsa_derive(out, pub, 33, other, 1));
    ASSERT(memcmp(out, secret, 33) == 0);

    ASSERT(btc_ecdsa_derive(out, pubconv, 65, other, 1));
    ASSERT(memcmp(out, secret, 33) == 0);

    ASSERT(btc_ecdsa_derive(out, pubhybrid, 65, other, 1));
    ASSERT(memcmp(out, secret, 33) == 0);

    ASSERT(btc_ecdsa_sign(out, &flag, msg, msg_len, priv));
    ASSERT(memcmp(out, sig, 64) == 0);
    ASSERT(flag == param);

    ASSERT(btc_ecdsa_verify(msg, msg_len, sig, pub, 33));
    ASSERT(btc_ecdsa_verify(msg, msg_len, sig, pubconv, 65));
    ASSERT(btc_ecdsa_verify(msg, msg_len, sig, pubhybrid, 65));

    msg[2] ^= 1;

    ASSERT(!btc_ecdsa_verify(msg, msg_len, sig, pub, 33));

    msg[2] ^= 1;
    sig[2] ^= 1;

    ASSERT(!btc_ecdsa_verify(msg, msg_len, sig, pub, 33));

    sig[2] ^= 1;
    pub[2] ^= 1;

    ASSERT(!btc_ecdsa_verify(msg, msg_len, sig, pub, 33));

    pub[2] ^= 1;

    ASSERT(btc_ecdsa_verify(msg, msg_len, sig, pub, 33));
  }
}

static void
test_ecdsa_random(void) {
  btc_drbg_t rng;
  int i;

  btc_drbg_init(&rng, NULL, 0);

  for (i = 0; i < 100; i++) {
    unsigned char entropy[32];
    unsigned char priv[32];
    unsigned char msg[32];
    unsigned char sig[64];
    unsigned char pub[65];
    unsigned char rec[65];
    unsigned int param;
    size_t k;

    btc_drbg_generate(&rng, entropy, sizeof(entropy));
    btc_drbg_generate(&rng, priv, sizeof(priv));
    btc_drbg_generate(&rng, msg, sizeof(msg));

    priv[0] &= 0x7f;

    ASSERT(btc_ecdsa_sign(sig, &param, msg, 32, priv));
    ASSERT(btc_ecdsa_pubkey_create(pub, priv, 1));
    ASSERT(btc_ecdsa_verify(msg, 32, sig, pub, 33));
    ASSERT(btc_ecdsa_recover(rec, msg, 32, sig, param, 1));
    ASSERT(memcmp(pub, rec, 33) == 0);

    k = priv[1] & 31;

    msg[k] ^= 1;

    ASSERT(!btc_ecdsa_verify(msg, 32, sig, pub, 33));

    msg[k] ^= 1;
    pub[k] ^= 1;

    ASSERT(!btc_ecdsa_verify(msg, 32, sig, pub, 33));

    pub[k] ^= 1;
    sig[k] ^= 1;

    ASSERT(!btc_ecdsa_verify(msg, 32, sig, pub, 33));

    sig[k] ^= 1;
    sig[32 + k] ^= 1;

    ASSERT(!btc_ecdsa_verify(msg, 32, sig, pub, 33));

    sig[32 + k] ^= 1;

    ASSERT(btc_ecdsa_verify(msg, 32, sig, pub, 33));
  }
}

static void
test_ecdsa_svdw(void) {
  static const unsigned char bytes[32] = {
    0xb0, 0xf0, 0xa9, 0x2d, 0x14, 0xa9, 0x82, 0xeb,
    0x12, 0x04, 0x78, 0x1a, 0x91, 0x6f, 0xdf, 0x38,
    0x2c, 0x4d, 0x84, 0x69, 0x38, 0xe6, 0x3f, 0x55,
    0xca, 0x59, 0x22, 0xb1, 0x0a, 0xb6, 0x82, 0xa0
  };

  static const unsigned char expect[33] = {
    0x02, 0xa3, 0xb0, 0xbc, 0xa2, 0xaa, 0x06, 0xe3,
    0x78, 0x83, 0x14, 0xb8, 0x73, 0x54, 0xbd, 0x01,
    0x04, 0xf1, 0x10, 0x85, 0xa8, 0x67, 0xab, 0xeb,
    0x4f, 0x43, 0xd2, 0xf6, 0x22, 0xdb, 0xb3, 0x29,
    0x20
  };

  unsigned char out[33];

  btc_ecdsa_pubkey_from_uniform(out, bytes, 1);

  ASSERT(btc_memcmp(out, expect, 33) == 0);
  ASSERT(btc_ecdsa_pubkey_to_uniform(out, expect, 33, 1));
  ASSERT(btc_memcmp(out, bytes, 32) == 0);
}

int main(void) {
  test_ecdsa_vectors();
  test_ecdsa_random();
  test_ecdsa_svdw();
  return 0;
}
