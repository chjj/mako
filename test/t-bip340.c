#include <stddef.h>
#include <string.h>
#include <satoshi/crypto/drbg.h>
#include <satoshi/crypto/ecc.h>
#include "data/bip340_vectors.h"
#include "tests.h"

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

int main(void) {
  test_bip340_vectors();
  test_bip340_random();
  return 0;
}
