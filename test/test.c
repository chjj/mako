#undef NDEBUG

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <satoshi/coins.h>
#include <satoshi/crypto/drbg.h>
#include <satoshi/crypto/ecc.h>
#include <satoshi/script.h>
#include <satoshi/tx.h>
#include <satoshi/util.h>
#include "data/ecdsa_vectors.h"
#include "data/bip340_vectors.h"
#include "data/sighash_vectors.h"
#include "data/script_vectors.h"
#include "data/tx_valid_vectors.h"
#include "data/tx_invalid_vectors.h"

#define ASSERT assert
#define lengthof(x) (sizeof(x) / sizeof((x)[0]))

static int
char2nib(int ch) {
  if (ch >= '0' && ch <= '9')
    ch -= '0';
  else if (ch >= 'A' && ch <= 'F')
    ch -= 'A' - 10;
  else if (ch >= 'a' && ch <= 'f')
    ch -= 'a' - 10;
  else
    ch = 16;

  return ch;
}

static int
unhex(unsigned char *out, const char *str, size_t len) {
  size_t j = 0;
  int hi, lo;
  size_t i;

  if (len & 1)
    return 0;

  for (i = 0; i < len; i += 2) {
    hi = char2nib(str[i + 0]);

    if (hi >= 16)
      return 0;

    lo = char2nib(str[i + 1]);

    if (lo >= 16)
      return 0;

    out[j++] = (hi << 4) | lo;
  }

  return 1;
}

static void
hex_parse(unsigned char *out, size_t size, const char *str) {
  size_t len = strlen(str);

  ASSERT(len == size * 2);
  ASSERT(unhex(out, str, len));
}

static void
hex_decode(unsigned char *out, size_t *size, const char *str) {
  size_t len = strlen(str);

  ASSERT(len <= *size * 2);
  ASSERT(unhex(out, str, len));

  *size = len / 2;
}

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

    printf("  - ECDSA vector #%u\n", i + 1);

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

static void
test_bip340_vectors(void) {
  btc_scratch_t *scratch = btc_scratch_create(10);
  unsigned char priv[32];
  unsigned char pub[32];
  unsigned char aux[32];
  unsigned char msg[32];
  unsigned char sig[64];
  unsigned char out[64];
  const unsigned char *msgs[1];
  const unsigned char *pubs[1];
  const unsigned char *sigs[1];
  unsigned int i;

  for (i = 0; i < lengthof(bip340_vectors); i++) {
    size_t priv_len = sizeof(priv);
    size_t pub_len = sizeof(pub);
    size_t aux_len = sizeof(aux);
    size_t msg_len = sizeof(msg);
    size_t sig_len = sizeof(sig);
    int result = bip340_vectors[i].result;
    const char *comment = bip340_vectors[i].comment;

    printf("  - BIP340 vector #%u (%s)\n", i + 1, comment);

    hex_decode(priv, &priv_len, bip340_vectors[i].priv);
    hex_decode(pub, &pub_len, bip340_vectors[i].pub);
    hex_decode(aux, &aux_len, bip340_vectors[i].aux);
    hex_decode(msg, &msg_len, bip340_vectors[i].msg);
    hex_decode(sig, &sig_len, bip340_vectors[i].sig);

    ASSERT(priv_len == 0 || priv_len == 32);
    ASSERT(pub_len == 32);
    ASSERT(aux_len == 0 || aux_len == 32);
    ASSERT(msg_len == 32);
    ASSERT(sig_len == 64);

    if (aux_len == 0)
      memset(aux, 0, 32);

    if (priv_len > 0) {
      ASSERT(btc_bip340_privkey_verify(priv));
      ASSERT(btc_bip340_pubkey_create(out, priv));
      ASSERT(memcmp(out, pub, pub_len) == 0);
      ASSERT(btc_bip340_sign(out, msg, 32, priv, aux));
      ASSERT(memcmp(out, sig, sig_len) == 0);
    }

    ASSERT(btc_bip340_verify(msg, msg_len, sig, pub) == result);

    msgs[0] = msg;
    sigs[0] = sig;
    pubs[0] = pub;

    ASSERT(btc_bip340_verify_batch(msgs, &msg_len, sigs,
                                   pubs, 1, scratch) == result);
  }

  btc_scratch_destroy(scratch);
}

static void
test_bip340_random(void) {
  btc_drbg_t rng;
  int i;

  btc_drbg_init(&rng, NULL, 0);

  for (i = 0; i < 10; i++) {
    unsigned char entropy[32];
    unsigned char priv[32];
    unsigned char sig[64];
    unsigned char pub[32];
    unsigned char msg[32];
    unsigned char aux[32];

    btc_drbg_generate(&rng, entropy, sizeof(entropy));
    btc_drbg_generate(&rng, priv, sizeof(priv));
    btc_drbg_generate(&rng, msg, sizeof(msg));
    btc_drbg_generate(&rng, aux, sizeof(aux));

    priv[0] &= 0x7f;

    ASSERT(btc_bip340_sign(sig, msg, 32, priv, aux));
    ASSERT(btc_bip340_pubkey_create(pub, priv));
    ASSERT(btc_bip340_verify(msg, 32, sig, pub));

    msg[0] ^= 1;

    ASSERT(!btc_bip340_verify(msg, 32, sig, pub));

    msg[0] ^= 1;
    pub[1] ^= 1;

    ASSERT(!btc_bip340_verify(msg, 32, sig, pub));

    pub[1] ^= 1;
    sig[0] ^= 1;

    ASSERT(!btc_bip340_verify(msg, 32, sig, pub));

    sig[0] ^= 1;

    ASSERT(btc_bip340_verify(msg, 32, sig, pub));
  }
}

static void
test_sighash_vector(const test_sighash_vector_t *vec, size_t index) {
  btc_script_t script;
  uint8_t msg[32];
  btc_tx_t tx;

  printf("sighash vector #%d: %s\n", (int)index, vec->comments);

  btc_tx_init(&tx);
  btc_script_init(&script);

  assert(btc_tx_import(&tx, vec->tx_raw, vec->tx_len));

  btc_script_set(&script, vec->script_raw, vec->script_len);

  btc_script_get_subscript(&script, &script, 0);
  btc_script_remove_separators(&script, &script);

  btc_tx_sighash(msg, &tx, vec->index, &script, 0, vec->type, 0, NULL);

  assert(memcmp(msg, vec->expected, 32) == 0);

  btc_tx_clear(&tx);
  btc_script_clear(&script);
}

static void
test_script_vector(const test_script_vector_t *vec, size_t index) {
  btc_tx_t prev, tx;

  printf("script vector #%d: %s\n", (int)index, vec->comments);

  btc_tx_init(&prev);
  btc_tx_init(&tx);

  assert(btc_tx_import(&prev, vec->prev_raw, vec->prev_len));
  assert(btc_tx_import(&tx, vec->tx_raw, vec->tx_len));

  {
    const btc_script_t *input = &tx.inputs.items[0]->script;
    const btc_stack_t *witness = &tx.inputs.items[0]->witness;
    const btc_script_t *output = &prev.outputs.items[0]->script;
    int64_t value = prev.outputs.items[0]->value;
    unsigned int flags = vec->flags;
    btc_tx_cache_t cache;
    int ret;

    memset(&cache, 0, sizeof(cache));

    ret = btc_script_verify(input,
                            witness,
                            output,
                            &tx,
                            0,
                            value,
                            flags,
                            &cache);

    assert(ret == vec->expected);
  }

  btc_tx_clear(&prev);
  btc_tx_clear(&tx);
}

static void
test_tx_valid_vector(const test_valid_vector_t *vec, size_t index) {
  btc_coin_t *coin;
  btc_view_t *view;
  btc_tx_t tx;
  size_t i;

  printf("tx valid vector #%d: %s\n", (int)index, vec->comments);

  btc_tx_init(&tx);

  view = btc_view_create();

  assert(btc_tx_import(&tx, vec->tx_raw, vec->tx_len));

  for (i = 0; i < vec->coins_len; i++) {
    coin = btc_coin_create();

    assert(btc_output_import(&coin->output, vec->coins[i].output_raw,
                                            vec->coins[i].output_len));

    btc_view_put(view, &vec->coins[i].outpoint, coin);
  }

  if (strstr(vec->comments, "Coinbase") == vec->comments)
    assert(btc_tx_check_sanity(NULL, &tx));
  else
    assert(btc_tx_verify(&tx, view, vec->flags));

  btc_tx_clear(&tx);
  btc_view_destroy(view);
}

static void
test_tx_invalid_vector(const test_invalid_vector_t *vec, size_t index) {
  btc_coin_t *coin;
  btc_view_t *view;
  btc_tx_t tx;
  size_t i;

  printf("tx invalid vector #%d: %s\n", (int)index, vec->comments);

  btc_tx_init(&tx);

  view = btc_view_create();

  assert(btc_tx_import(&tx, vec->tx_raw, vec->tx_len));

  for (i = 0; i < vec->coins_len; i++) {
    coin = btc_coin_create();

    assert(btc_output_import(&coin->output, vec->coins[i].output_raw,
                                            vec->coins[i].output_len));

    btc_view_put(view, &vec->coins[i].outpoint, coin);
  }

  if (strcmp(vec->comments, "Duplicate inputs") == 0) {
    assert(btc_tx_verify(&tx, view, vec->flags));
    assert(!btc_tx_check_sanity(NULL, &tx));
  } else if (strcmp(vec->comments, "Negative output") == 0) {
    assert(btc_tx_verify(&tx, view, vec->flags));
    assert(!btc_tx_check_sanity(NULL, &tx));
  } else if (strstr(vec->comments, "Coinbase") == vec->comments) {
    assert(!btc_tx_check_sanity(NULL, &tx));
  } else {
    assert(!btc_tx_verify(&tx, view, vec->flags));
  }

  btc_tx_clear(&tx);
  btc_view_destroy(view);
}

static void
test_sighash(void) {
  size_t i;

  for (i = 0; i < lengthof(test_sighash_vectors); i++)
    test_sighash_vector(&test_sighash_vectors[i], i);
}

static void
test_script(void) {
  size_t i;

  for (i = 0; i < lengthof(test_script_vectors); i++)
    test_script_vector(&test_script_vectors[i], i);
}

static void
test_tx_valid(void) {
  size_t i;

  for (i = 0; i < lengthof(test_valid_vectors); i++)
    test_tx_valid_vector(&test_valid_vectors[i], i);
}

static void
test_tx_invalid(void) {
  size_t i;

  for (i = 0; i < lengthof(test_invalid_vectors); i++)
    test_tx_invalid_vector(&test_invalid_vectors[i], i);
}

#include <node/db.h>

static void
test_db(void) {
  static const unsigned char key1[] = "foo";
  static const unsigned char key2[] = "bar";
  static const unsigned char key3[] = "baz";
  static const unsigned char val1[] = "one";
  static const unsigned char val2[] = "two";
  static const unsigned char val3[] = "three";
  unsigned char *val;
  size_t vlen;

  btc_db_t *db = btc_db_create();

  ASSERT(btc_db_open(db, "/tmp/btc_db_test", 10 << 20));

  ASSERT(btc_db_put(db, key1, sizeof(key1), val1, sizeof(val1)));
  ASSERT(btc_db_put(db, key2, sizeof(key2), val2, sizeof(val2)));
  ASSERT(btc_db_put(db, key3, sizeof(key3), val3, sizeof(val3)));

  ASSERT(btc_db_get(db, &val, &vlen, key1, sizeof(key1)));
  ASSERT(vlen == sizeof(val1) && memcmp(val, val1, vlen) == 0);

  ASSERT(btc_db_get(db, &val, &vlen, key2, sizeof(key2)));
  ASSERT(vlen == sizeof(val2) && memcmp(val, val2, vlen) == 0);

  ASSERT(btc_db_get(db, &val, &vlen, key3, sizeof(key3)));
  ASSERT(vlen == sizeof(val3) && memcmp(val, val3, vlen) == 0);
}

int main(void) {
  test_ecdsa_vectors();
  test_ecdsa_random();
  test_ecdsa_svdw();
  test_bip340_vectors();
  test_bip340_random();
  test_sighash();
  test_script();
  test_tx_valid();
  test_tx_invalid();
  test_db();
  return 0;
}
