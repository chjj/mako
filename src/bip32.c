/*!
 * bip32.c - bip32 for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <satoshi/bip32.h>
#include <satoshi/encoding.h>
#include <satoshi/network.h>
#include <satoshi/crypto/ecc.h>
#include <satoshi/crypto/hash.h>
#include <satoshi/crypto/rand.h>
#include <satoshi/util.h>
#include "bio.h"
#include "internal.h"

/*
 * Helpers
 */

static int
parse_path(uint32_t *zp, const char *xp, int hard) {
  int zn = 0;
  uint32_t z;
  int n, ch;

  if (*xp != 'm' && *xp != 'M')
    return -1;

  xp++;

  if (*xp == '\'')
    xp++;

  if (*xp == '\0')
    return zn;

  if (*xp != '/')
    return -1;

  xp++;

  for (;;) {
    z = 0;
    n = 0;

    for (;;) {
      ch = *xp;

      if (ch < '0' || ch > '9')
        break;

      if (++n > 10)
        return -1;

      z *= 10;
      z += ch - '0';

      xp++;
    }

    if (n == 0)
      return -1;

    if (hard && *xp == '\'') {
      z |= BTC_BIP32_HARDEN;
      xp++;
    }

    if (zn == BTC_BIP32_MAX_DEPTH)
      return -1;

    zp[zn++] = z;

    if (*xp == '\0')
      return zn;

    if (*xp != '/')
      return -1;

    xp++;
  }
}

static int
find_prefix(const uint32_t *table, uint32_t prefix) {
  int length = lengthof(((btc_network_t *)0)->key.xpubkey);
  int i;

  for (i = 0; i < length; i++) {
    if (table[i] == prefix)
      return i;
  }

  return -1;
}

/*
 * Common
 */

static void
btc_hdnode_init(btc_hdnode_t *node) {
  static const uint8_t g[33] = {
    0x02,
    0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac,
    0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
    0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9,
    0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98
  };

  memset(node, 0, sizeof(*node));

  node->seckey[31] = 1;

  memcpy(node->pubkey, g, sizeof(g));
}

static void
btc_hdnode_clear(btc_hdnode_t *node) {
  btc_memzero(node, sizeof(*node));
}

static void
btc_hdnode_copy(btc_hdnode_t *z, const btc_hdnode_t *x) {
  if (z != x)
    *z = *x;
}

static uint32_t
btc_hdnode_fingerprint(const btc_hdnode_t *node) {
  uint8_t hash[20];

  btc_hash160(hash, node->pubkey, 33);

  return btc_read32be(hash);
}

/*
 * HD Private
 */

void
btc_hdpriv_init(btc_hdnode_t *node) {
  btc_hdnode_init(node);
}

void
btc_hdpriv_clear(btc_hdnode_t *node) {
  btc_hdnode_clear(node);
}

void
btc_hdpriv_copy(btc_hdnode_t *z, const btc_hdnode_t *x) {
  btc_hdnode_copy(z, x);
}

int
btc_hdpriv_set(btc_hdnode_t *node,
               enum btc_bip32_type type,
               const uint8_t *seckey,
               const uint8_t *entropy) {
  node->type = type;
  node->depth = 0;
  node->parent = 0;
  node->index = 0;

  memcpy(node->chain, entropy, 32);
  memcpy(node->seckey, seckey, 32);

  return btc_ecdsa_pubkey_create(node->pubkey, seckey, 1);
}

void
btc_hdpriv_generate(btc_hdnode_t *node, enum btc_bip32_type type) {
  uint8_t seed[64];

  btc_getrandom(seed, 64);

  btc_ecdsa_privkey_generate(seed, seed);

  CHECK(btc_hdpriv_set(node, type, seed, seed + 32));

  btc_memzero(seed, sizeof(seed));
}

int
btc_hdpriv_derive(btc_hdnode_t *child,
                  const btc_hdnode_t *node,
                  uint32_t index,
                  int harden) {
  static const uint8_t zero[1] = {0};
  btc_hmac512_t ctx;
  uint8_t seckey[32];
  uint8_t hash[64];
  uint8_t tmp[4];

  if (node->depth == BTC_BIP32_MAX_DEPTH)
    return 0; /* LCOV_EXCL_LINE */

  if (harden)
    index |= BTC_BIP32_HARDEN;

retry:
  btc_write32be(tmp, index);

  btc_hmac512_init(&ctx, node->chain, 32);

  if (index & BTC_BIP32_HARDEN) {
    btc_hmac512_update(&ctx, zero, 1);
    btc_hmac512_update(&ctx, node->seckey, 32);
  } else {
    btc_hmac512_update(&ctx, node->pubkey, 33);
  }

  btc_hmac512_update(&ctx, tmp, 4);
  btc_hmac512_final(&ctx, hash);

  if (!btc_ecdsa_privkey_tweak_add(seckey, node->seckey, hash)) {
    if (!btc_ecdsa_privkey_verify(node->seckey))
      btc_abort(); /* LCOV_EXCL_LINE */

    if (index & BTC_BIP32_HARDEN) {
      if (++index == 0)
        return 0; /* LCOV_EXCL_LINE */
    } else {
      if (++index & BTC_BIP32_HARDEN)
        return 0; /* LCOV_EXCL_LINE */
    }

    goto retry;
  }

  child->type = node->type;
  child->depth = node->depth + 1;
  child->parent = btc_hdnode_fingerprint(node);
  child->index = index;

  memcpy(child->chain, hash + 32, 32);
  memcpy(child->seckey, seckey, 32);

  CHECK(btc_ecdsa_pubkey_create(child->pubkey, seckey, 1));

  btc_memzero(seckey, sizeof(seckey));
  btc_memzero(hash, sizeof(hash));
  btc_memzero(tmp, sizeof(tmp));
  btc_memzero(&ctx, sizeof(ctx));

  return 1;
}

int
btc_hdpriv_path(btc_hdnode_t *child,
                const btc_hdnode_t *node,
                const char *path) {
  uint32_t indices[BTC_BIP32_MAX_DEPTH];
  int i, len;

  len = parse_path(indices, path, 1);

  if (len < 0)
    return 0;

  if ((int)node->depth + len > BTC_BIP32_MAX_DEPTH)
    return 0; /* LCOV_EXCL_LINE */

  btc_hdnode_copy(child, node);

  for (i = 0; i < len; i++) {
    if (!btc_hdpriv_derive(child, child, indices[i], 0))
      return 0; /* LCOV_EXCL_LINE */
  }

  return 1;
}

int
btc_hdpriv_account(btc_hdnode_t *child,
                   const btc_hdnode_t *node,
                   uint32_t purpose,
                   uint32_t type,
                   uint32_t account) {
  if (!btc_hdpriv_derive(child, node, purpose, 1))
    return 0; /* LCOV_EXCL_LINE */

  if (!btc_hdpriv_derive(child, child, type, 1))
    return 0; /* LCOV_EXCL_LINE */

  if (!btc_hdpriv_derive(child, child, account, 1))
    return 0; /* LCOV_EXCL_LINE */

  return 1;
}

int
btc_hdpriv_leaf(btc_hdnode_t *child,
                const btc_hdnode_t *node,
                uint32_t branch,
                uint32_t index) {
  if (!btc_hdpriv_derive(child, node, branch, 0))
    return 0; /* LCOV_EXCL_LINE */

  if (!btc_hdpriv_derive(child, child, index, 0))
    return 0; /* LCOV_EXCL_LINE */

  return 1;
}

void
btc_hdpriv_export(uint8_t *data,
                  const btc_hdnode_t *node,
                  const btc_network_t *network) {
  uint32_t prefix = network->key.xprvkey[node->type];

  btc_write32be(data + 0, prefix);

  data[4] = node->depth;

  btc_write32be(data + 5, node->parent);
  btc_write32be(data + 9, node->index);

  memcpy(data + 13, node->chain, 32);

  data[45] = 0;

  memcpy(data + 46, node->seckey, 32);

  btc_write32le(data + 78, btc_checksum(data, 78));
}

int
btc_hdpriv_import(btc_hdnode_t *node,
                  const uint8_t *data,
                  const btc_network_t *network) {
  uint32_t prefix = btc_read32be(data + 0);
  int type = find_prefix(network->key.xprvkey, prefix);

  if (type < 0)
    return 0;

  node->type = (enum btc_bip32_type)type;
  node->depth = data[4];
  node->parent = btc_read32be(data + 5);
  node->index = btc_read32be(data + 9);

  memcpy(node->chain, data + 13, 32);

  if (data[45] != 0)
    return 0;

  memcpy(node->seckey, data + 46, 32);

  if (btc_read32le(data + 78) != btc_checksum(data, 78))
    return 0;

  if (!btc_ecdsa_pubkey_create(node->pubkey, node->seckey, 1))
    return 0;

  return 1;
}

size_t
btc_hdpriv_size(const btc_hdnode_t *node) {
  (void)node;
  return 82;
}

uint8_t *
btc_hdpriv_write(uint8_t *zp,
                 const btc_hdnode_t *x,
                 const btc_network_t *network) {
  btc_hdpriv_export(zp, x, network);
  return zp + 82;
}

int
btc_hdpriv_read(btc_hdnode_t *z,
                const uint8_t **xp,
                size_t *xn,
                const btc_network_t *network) {
  if (*xn < 82)
    return 0;

  if (!btc_hdpriv_import(z, *xp, network))
    return 0;

  *xp += 82;
  *xn -= 82;

  return 1;
}

void
btc_hdpriv_get_str(char *str,
                   const btc_hdnode_t *node,
                   const btc_network_t *network) {
  uint8_t data[82];

  btc_hdpriv_export(data, node, network);

  CHECK(btc_base58_encode(str, NULL, data, 82));

  btc_memzero(data, sizeof(data));
}

int
btc_hdpriv_set_str(btc_hdnode_t *node,
                   const char *str,
                   const btc_network_t *network) {
  size_t len = strlen(str);
  uint8_t data[115];
  int ret = 0;

  if (len > sizeof(data))
    return 0;

  if (!btc_base58_decode(data, &len, str, len))
    goto fail;

  if (len != 82)
    goto fail;

  if (!btc_hdpriv_import(node, data, network))
    goto fail;

  ret = 1;
fail:
  btc_memzero(data, sizeof(data));
  return ret;
}

/*
 * HD Public
 */

void
btc_hdpub_init(btc_hdnode_t *node) {
  btc_hdnode_init(node);

  node->seckey[31] = 0;
}

void
btc_hdpub_clear(btc_hdnode_t *node) {
  btc_hdnode_clear(node);
}

void
btc_hdpub_copy(btc_hdnode_t *z, const btc_hdnode_t *x) {
  btc_hdnode_copy(z, x);
}

int
btc_hdpub_set(btc_hdnode_t *node,
              enum btc_bip32_type type,
              const uint8_t *pubkey,
              const uint8_t *entropy) {
  node->type = type;
  node->depth = 0;
  node->parent = 0;
  node->index = 0;

  memcpy(node->chain, entropy, 32);

  btc_memzero(node->seckey, 32);

  memcpy(node->pubkey, pubkey, 33);

  return btc_ecdsa_pubkey_verify(node->pubkey, 33);
}

void
btc_hdpub_set_hdpriv(btc_hdnode_t *z, const btc_hdnode_t *x) {
  btc_hdnode_copy(z, x);
  btc_memzero(z->seckey, 32);
}

int
btc_hdpub_derive(btc_hdnode_t *child,
                 const btc_hdnode_t *node,
                 uint32_t index) {
  btc_hmac512_t ctx;
  uint8_t pubkey[33];
  uint8_t hash[64];
  uint8_t tmp[4];

  if (node->depth == BTC_BIP32_MAX_DEPTH)
    return 0; /* LCOV_EXCL_LINE */

  if (index & BTC_BIP32_HARDEN)
    return 0; /* LCOV_EXCL_LINE */

retry:
  btc_write32be(tmp, index);

  btc_hmac512_init(&ctx, node->chain, 32);
  btc_hmac512_update(&ctx, node->pubkey, 33);
  btc_hmac512_update(&ctx, tmp, 4);
  btc_hmac512_final(&ctx, hash);

  if (!btc_ecdsa_pubkey_tweak_add(pubkey, node->pubkey, 33, hash, 1)) {
    if (!btc_ecdsa_pubkey_verify(node->pubkey, 33))
      btc_abort(); /* LCOV_EXCL_LINE */

    if (++index & BTC_BIP32_HARDEN)
      return 0; /* LCOV_EXCL_LINE */

    goto retry;
  }

  child->type = node->type;
  child->depth = node->depth + 1;
  child->parent = btc_hdnode_fingerprint(node);
  child->index = index;

  memcpy(child->chain, hash + 32, 32);

  btc_memzero(child->seckey, 32);

  memcpy(child->pubkey, pubkey, 33);

  btc_memzero(pubkey, sizeof(pubkey));
  btc_memzero(hash, sizeof(hash));
  btc_memzero(tmp, sizeof(tmp));
  btc_memzero(&ctx, sizeof(ctx));

  return 1;
}

int
btc_hdpub_path(btc_hdnode_t *child,
               const btc_hdnode_t *node,
               const char *path) {
  uint32_t indices[BTC_BIP32_MAX_DEPTH];
  int i, len;

  len = parse_path(indices, path, 0);

  if (len < 0)
    return 0;

  if ((int)node->depth + len > BTC_BIP32_MAX_DEPTH)
    return 0; /* LCOV_EXCL_LINE */

  btc_hdnode_copy(child, node);

  for (i = 0; i < len; i++) {
    if (!btc_hdpub_derive(child, child, indices[i]))
      return 0; /* LCOV_EXCL_LINE */
  }

  return 1;
}

int
btc_hdpub_leaf(btc_hdnode_t *child,
               const btc_hdnode_t *node,
               uint32_t branch,
               uint32_t index) {
  if (!btc_hdpub_derive(child, node, branch))
    return 0; /* LCOV_EXCL_LINE */

  if (!btc_hdpub_derive(child, child, index))
    return 0; /* LCOV_EXCL_LINE */

  return 1;
}

void
btc_hdpub_export(uint8_t *data,
                 const btc_hdnode_t *node,
                 const btc_network_t *network) {
  uint32_t prefix = network->key.xpubkey[node->type];

  btc_write32be(data + 0, prefix);

  data[4] = node->depth;

  btc_write32be(data + 5, node->parent);
  btc_write32be(data + 9, node->index);

  memcpy(data + 13, node->chain, 32);
  memcpy(data + 45, node->pubkey, 33);

  btc_write32le(data + 78, btc_checksum(data, 78));
}

int
btc_hdpub_import(btc_hdnode_t *node,
                 const uint8_t *data,
                 const btc_network_t *network) {
  uint32_t prefix = btc_read32be(data + 0);
  int type = find_prefix(network->key.xpubkey, prefix);

  if (type < 0)
    return 0;

  node->type = (enum btc_bip32_type)type;
  node->depth = data[4];
  node->parent = btc_read32be(data + 5);
  node->index = btc_read32be(data + 9);

  memcpy(node->chain, data + 13, 32);

  btc_memzero(node->seckey, 32);

  memcpy(node->pubkey, data + 45, 33);

  if (btc_read32le(data + 78) != btc_checksum(data, 78))
    return 0;

  if (!btc_ecdsa_pubkey_verify(node->pubkey, 33))
    return 0;

  return 1;
}

size_t
btc_hdpub_size(const btc_hdnode_t *node) {
  (void)node;
  return 82;
}

uint8_t *
btc_hdpub_write(uint8_t *zp,
                const btc_hdnode_t *x,
                const btc_network_t *network) {
  btc_hdpub_export(zp, x, network);
  return zp + 82;
}

int
btc_hdpub_read(btc_hdnode_t *z,
               const uint8_t **xp,
               size_t *xn,
               const btc_network_t *network) {
  if (*xn < 82)
    return 0;

  if (!btc_hdpub_import(z, *xp, network))
    return 0;

  *xp += 82;
  *xn -= 82;

  return 1;
}

void
btc_hdpub_get_str(char *str,
                  const btc_hdnode_t *node,
                  const btc_network_t *network) {
  uint8_t data[82];

  btc_hdpub_export(data, node, network);

  CHECK(btc_base58_encode(str, NULL, data, 82));

  btc_memzero(data, sizeof(data));
}

int
btc_hdpub_set_str(btc_hdnode_t *node,
                  const char *str,
                  const btc_network_t *network) {
  size_t len = strlen(str);
  uint8_t data[115];
  int ret = 0;

  if (len > sizeof(data))
    return 0;

  if (!btc_base58_decode(data, &len, str, len))
    goto fail;

  if (len != 82)
    goto fail;

  if (!btc_hdpub_import(node, data, network))
    goto fail;

  ret = 1;
fail:
  btc_memzero(data, sizeof(data));
  return ret;
}
