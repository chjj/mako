/*!
 * master.c - wallet master key for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <io/core.h>

#include <mako/crypto/hash.h>
#include <mako/crypto/ies.h>
#include <mako/crypto/rand.h>

#include <mako/address.h>
#include <mako/buffer.h>
#include <mako/bip32.h>
#include <mako/bip39.h>
#include <mako/network.h>
#include <mako/util.h>

#include "../impl.h"
#include "../internal.h"

#include "master.h"

/*
 * Constants
 */

#define MAX_PLAINTEXT_SIZE (BTC_MNEMONIC_SIZE + BTC_HDNODE_SIZE) /* 179 */

/*
 * Master Key
 */

void
btc_master_init(btc_master_t *key, const btc_network_t *network) {
  key->network = network;
  key->type = BTC_BIP32_P2WPKH;

  btc_mnemonic_init(&key->mnemonic);
  btc_hdpriv_init(&key->chain);

  key->locked = 0;
  key->deadline = 0;
  key->algorithm = BTC_KDF_NONE;

  memset(key->nonce, 0, 24);

  key->N = 0;
  key->r = 0;
  key->p = 0;

  btc_buffer_init(&key->payload);
}

void
btc_master_clear(btc_master_t *key) {
  btc_mnemonic_clear(&key->mnemonic);
  btc_hdpriv_clear(&key->chain);
  btc_buffer_clear(&key->payload);
}

void
btc_master_reset(btc_master_t *key) {
  btc_buffer_clear(&key->payload);
  btc_master_init(key, key->network);
}

static size_t
btc_plaintext_size(const btc_master_t *key) {
  return btc_mnemonic_size(&key->mnemonic)
       + btc_hdpriv_size(&key->chain);
}

static uint8_t *
btc_plaintext_write(uint8_t *zp, const btc_master_t *x) {
  zp = btc_mnemonic_write(zp, &x->mnemonic);
  zp = btc_hdpriv_write(zp, &x->chain, x->network);
  return zp;
}

static int
btc_plaintext_read(btc_master_t *z, const uint8_t **xp, size_t *xn) {
  if (!btc_mnemonic_read(&z->mnemonic, xp, xn))
    return 0;

  if (!btc_hdpriv_read(&z->chain, xp, xn, z->network))
    return 0;

  return 1;
}

static int
btc_plaintext_import(btc_master_t *z, const uint8_t *xp, size_t xn) {
  return btc_plaintext_read(z, &xp, &xn);
}

static void
btc_plaintext_set(btc_buffer_t *z, const btc_master_t *x) {
  size_t zn = btc_plaintext_size(x);
  uint8_t *zp = btc_buffer_resize(z, zn);

  btc_plaintext_write(zp, x);
}

size_t
btc_master_size(const btc_master_t *key) {
  return 42 + btc_buffer_size(&key->payload);
}

uint8_t *
btc_master_write(uint8_t *zp, const btc_master_t *x) {
  zp = btc_uint8_write(zp, x->type);
  zp = btc_uint8_write(zp, x->algorithm);
  zp = btc_raw_write(zp, x->nonce, 24);
  zp = btc_uint64_write(zp, x->N);
  zp = btc_uint32_write(zp, x->r);
  zp = btc_uint32_write(zp, x->p);
  zp = btc_buffer_write(zp, &x->payload);
  return zp;
}

int
btc_master_read(btc_master_t *z, const uint8_t **xp, size_t *xn) {
  uint8_t type;

  btc_master_reset(z);

  if (!btc_uint8_read(&type, xp, xn))
    return 0;

  z->type = (enum btc_bip32_type)type;

  if (!btc_uint8_read(&z->algorithm, xp, xn))
    return 0;

  if (!btc_raw_read(z->nonce, 24, xp, xn))
    return 0;

  if (!btc_uint64_read(&z->N, xp, xn))
    return 0;

  if (!btc_uint32_read(&z->r, xp, xn))
    return 0;

  if (!btc_uint32_read(&z->p, xp, xn))
    return 0;

  if (!btc_buffer_read(&z->payload, xp, xn))
    return 0;

  if (z->algorithm == BTC_KDF_NONE) {
    if (!btc_plaintext_import(z, z->payload.data, z->payload.length))
      return 0;
  } else {
    z->locked = 1;
  }

  return 1;
}

size_t
btc_master_export(uint8_t *zp, const btc_master_t *x) {
  return btc_master_write(zp, x) - zp;
}

int
btc_master_import(btc_master_t *z, const uint8_t *xp, size_t xn) {
  return btc_master_read(z, &xp, &xn);
}

static int
btc_master_derive(uint8_t *ck, const btc_master_t *key, const char *pass) {
  switch (key->algorithm) {
    case BTC_KDF_NONE: {
      memset(ck, 0, 32);
      return 1;
    }

    case BTC_KDF_PBKDF2: {
      btc_pbkdf512_derive(ck, (const uint8_t *)pass,
                              strlen(pass),
                              key->nonce,
                              24,
                              key->N,
                              32);
      return 1;
    }

#if 0
    case BTC_KDF_SCRYPT: {
      return btc_scrypt_derive(ck, (const uint8_t *)pass,
                                   strlen(pass),
                                   key->nonce,
                                   24,
                                   key->N,
                                   key->r,
                                   key->p,
                                   32);
    }
#endif

    default: {
      btc_abort();
      return 0;
    }
  }
}

int
btc_master_encrypt(btc_master_t *key, uint8_t algorithm, const char *pass) {
  uint8_t ct[16 + MAX_PLAINTEXT_SIZE];
  uint8_t pt[MAX_PLAINTEXT_SIZE];
  uint8_t ck[32];
  size_t pn;

  if (key->locked)
    return 0;

  switch (algorithm) {
    case BTC_KDF_NONE: {
      key->algorithm = BTC_KDF_NONE;
      key->N = 0;
      key->r = 0;
      key->p = 0;
      break;
    }

    case BTC_KDF_PBKDF2: {
      key->algorithm = BTC_KDF_PBKDF2;
      key->N = 50000;
      key->r = 0;
      key->p = 0;
      break;
    }

    case BTC_KDF_SCRYPT: {
      key->algorithm = BTC_KDF_SCRYPT;
      key->N = 16384;
      key->r = 8;
      key->p = 1;
      break;
    }

    default: {
      return 0;
    }
  }

  pn = btc_plaintext_write(pt, key) - pt;

  if (key->algorithm == BTC_KDF_NONE) {
    btc_memzero(key->nonce, 24);

    btc_buffer_set(&key->payload, pt, pn);
  } else {
    btc_getrandom(key->nonce, 24);

    if (!btc_master_derive(ck, key, pass))
      return 0;

    btc_secretbox_seal(ct, pt, pn, ck, key->nonce);

    btc_buffer_set(&key->payload, ct, pn + 16);

    btc_mnemonic_clear(&key->mnemonic);
    btc_hdpriv_clear(&key->chain);

    key->locked = 1;
  }

  key->deadline = 0;

  btc_memzero(ct, sizeof(ct));
  btc_memzero(pt, sizeof(pt));
  btc_memzero(ck, sizeof(ck));

  return 1;
}

void
btc_master_lock(btc_master_t *key) {
  if (key->algorithm == BTC_KDF_NONE)
    return;

  btc_mnemonic_clear(&key->mnemonic);
  btc_hdpriv_clear(&key->chain);

  key->locked = 1;
  key->deadline = 0;
}

void
btc_master_maybe_lock(btc_master_t *key) {
  if (key->algorithm == BTC_KDF_NONE)
    return;

  if (key->locked || key->deadline == 0)
    return;

  if (btc_time_msec() >= key->deadline)
    btc_master_lock(key);
}

int
btc_master_unlock(btc_master_t *key, const char *pass, int64_t msec) {
  const uint8_t *xp = key->payload.data;
  size_t xn = key->payload.length;
  uint8_t pt[MAX_PLAINTEXT_SIZE];
  uint8_t ck[32];

  if (!key->locked)
    return 1;

  if (pass == NULL)
    return 0;

  if (xn < 16 || xn > 16 + MAX_PLAINTEXT_SIZE)
    return 0;

  if (!btc_master_derive(ck, key, pass))
    return 0;

  if (!btc_secretbox_open(pt, xp, xn, ck, key->nonce))
    return 0;

  if (!btc_plaintext_import(key, pt, xn - 16))
    return 0;

  key->locked = 0;
  key->deadline = msec >= 0 ? btc_time_msec() + msec : 0;

  btc_memzero(pt, sizeof(pt));
  btc_memzero(ck, sizeof(ck));

  return 1;
}

void
btc_master_generate(btc_master_t *key, enum btc_bip32_type type) {
  int r;

  btc_master_reset(key);

  key->type = type;

  do {
    btc_mnemonic_generate(&key->mnemonic, 256);

    r = btc_hdpriv_set_mnemonic(&key->chain, type,
                                &key->mnemonic, 0);
  } while (r == 0);

  btc_plaintext_set(&key->payload, key);
}

int
btc_master_import_mnemonic(btc_master_t *key,
                           enum btc_bip32_type type,
                           const btc_mnemonic_t *mnemonic) {
  btc_master_reset(key);

  key->type = type;

  if (!btc_hdpriv_set_mnemonic(&key->chain, type, mnemonic, 0))
    return 0;

  btc_mnemonic_copy(&key->mnemonic, mnemonic);

  btc_plaintext_set(&key->payload, key);

  return 1;
}

void
btc_master_import_chain(btc_master_t *key, const btc_hdnode_t *node) {
  btc_master_reset(key);

  key->type = node->type;

  btc_hdpriv_copy(&key->chain, node);
  btc_plaintext_set(&key->payload, key);
}

int
btc_master_account(btc_hdnode_t *node,
                   const btc_master_t *key,
                   uint32_t account) {
  uint32_t type = key->network->key.coin_type;
  uint32_t purpose;

  if (key->locked)
    return 0;

  purpose = btc_bip32_purpose[key->chain.type];

  return btc_hdpriv_account(node,
                            &key->chain,
                            purpose,
                            type,
                            account);
}

int
btc_master_leaf(btc_hdnode_t *leaf,
                const btc_master_t *key,
                const btc_path_t *path) {
  if (!btc_master_account(leaf, key, path->account))
    return 0;

  return btc_hdpriv_leaf(leaf, leaf, path->change,
                                     path->index);
}
