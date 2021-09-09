static wei_curve_t *btc_secp256k1;

void
btc_ripemd160(uint8_t *out, const uint8_t *data, size_t size) {
  ripemd160_t ctx;
  ripemd160_init(&ctx);
  ripemd160_update(&ctx, data, size);
  ripemd160_final(&ctx, out);
}

void
btc_sha1(uint8_t *out, const uint8_t *data, size_t size) {
  sha1_t ctx;
  sha1_init(&ctx);
  sha1_update(&ctx, data, size);
  sha1_final(&ctx, out);
}

void
btc_sha256(uint8_t *out, const uint8_t *data, size_t size) {
  sha256_t ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, data, size);
  sha256_final(&ctx, out);
}

void
btc_hash160(uint8_t *out, const uint8_t *data, size_t size) {
  hash160_t ctx;
  hash160_init(&ctx);
  hash160_update(&ctx, data, size);
  hash160_final(&ctx, out);
}

void
btc_hash256(uint8_t *out, const uint8_t *data, size_t size) {
  hash256_t ctx;
  hash256_init(&ctx);
  hash256_update(&ctx, data, size);
  hash256_final(&ctx, out);
}

void
btc_getrandom(void *dst, size_t size) {
  CHECK(torsion_getrandom(dst, size));
}

uint32_t
btc_random(void) {
  uint32_t z;

  CHECK(torsion_random(&z));

  return z;
}

uint32_t
btc_uniform(uint32_t max) {
  uint32_t z;

  CHECK(torsion_uniform(&z, max));

  return z;
}

static const wei_curve_t *
btc_curve(void) {
  /* TODO: Add a constructor for this. */
  if (btc_secp256k1 == NULL)
    btc_secp256k1 = wei_curve_create(WEI_CURVE_SECP256K1);

  return btc_secp256k1;
}

void
btc_ecdsa_privkey_generate(uint8_t *out) {
  uint8_t entropy[32];

  btc_getrandom(entropy, 32);

  ecdsa_privkey_generate(btc_curve(), out, entropy);

  torsion_memzero(entropy, 32);
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
  uint8_t sig[64];

  if (!ecdsa_sig_import(ec, sig, der, der_len))
    return 0;

  return ecdsa_is_low_s(btc_curve(), sig);
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

  torsion_memzero(aux, 32);

  return ret;
}

int
btc_bip340_verify(const uint8_t *msg, const uint8_t *sig, const uint8_t *pub) {
  return bip340_verify(btc_curve(), msg, 32, sig, pub);
}

/* Notes about unbalanced merkle trees:
 *
 * Bitcoin hashes odd nodes with themselves,
 * allowing an attacker to add a duplicate
 * TXID, creating an even number of leaves
 * and computing the same root (CVE-2012-2459).
 * In contrast, RFC 6962 simply propagates
 * odd nodes up.
 *
 * RFC 6962:
 *
 *              R
 *             / \
 *            /   \
 *           /     \
 *          /       \
 *         /         \
 *        k           j <-- same as below
 *       / \          |
 *      /   \         |
 *     /     \        |
 *    h       i       j
 *   / \     / \     / \
 *  a   b   c   d   e   f
 *
 * Bitcoin Behavior:
 *
 *              R
 *             / \
 *            /   \
 *           /     \
 *          /       \
 *         /         \
 *        k           l <-- HASH(j || j)
 *       / \          |
 *      /   \         |
 *     /     \        |
 *    h       i       j
 *   / \     / \     / \
 *  a   b   c   d   e   f
 *
 * This creates a situation where these leaves:
 *
 *        R
 *       / \
 *      /   \
 *     /     \
 *    d       e <-- HASH(c || c)
 *   / \     / \
 *  a   b   c   c
 *
 * Compute the same root as:
 *
 *       R
 *      / \
 *     /   \
 *    d     e <-- HASH(c || c)
 *   / \    |
 *  a   b   c
 *
 * Why does this matter? Duplicate TXIDs are
 * invalid right? They're spending the same
 * inputs! The problem arises in certain
 * implementation optimizations which may
 * mark a block hash invalid. In other words,
 * an invalid block shares the same block
 * hash as a valid one!
 *
 * See:
 *   https://tools.ietf.org/html/rfc6962#section-2.1
 *   https://nvd.nist.gov/vuln/detail/CVE-2012-2459
 *   https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-2459
 *   https://bitcointalk.org/?topic=81749
 */

int
btc_merkle_root(uint8_t *root, uint8_t *nodes, size_t size) {
  uint8_t *left, *right, *last;
  int malleated = 0;
  hash256_t ctx;
  size_t i;

  if (size == 0) {
    memset(root, 0, 32);
    return 1;
  }

  last = &nodes[0 * 32];

  while (size > 1) {
    for (i = 0; i < size; i += 2) {
      left = &nodes[(i + 0) * 32];
      right = left;

      if (i + 1 < size) {
        right = &nodes[(i + 1) * 32];

        if (i + 2 == size && memcmp(left, right, 32) == 0)
          malleated = 1;
      }

      last = &nodes[(i / 2) * 32];

      hash256_init(&ctx);
      hash256_update(&ctx, left, 32);
      hash256_update(&ctx, right, 32);
      hash256_final(&ctx, last);
    }

    size = (size + 1) / 2;
  }

  memcpy(root, last, 32);

  return malleated == 0;
}
