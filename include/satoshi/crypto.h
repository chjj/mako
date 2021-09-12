/*!
 * crypto.h - crypto for libsatoshi
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef BTC_CRYPTO_H
#define BTC_CRYPTO_H

#include <stddef.h>
#include <stdint.h>
#include "common.h"
#include "impl.h"
#include "types.h"

/*
 * Crypto
 */

BTC_EXTERN void
btc_ripemd160(uint8_t *out, const uint8_t *data, size_t size);

BTC_EXTERN void
btc_sha1(uint8_t *out, const uint8_t *data, size_t size);

BTC_EXTERN void
btc_sha256(uint8_t *out, const uint8_t *data, size_t size);

BTC_EXTERN void
btc_hash160(uint8_t *out, const uint8_t *data, size_t size);

BTC_EXTERN void
btc_hash256(uint8_t *out, const uint8_t *data, size_t size);

BTC_EXTERN void
btc_getrandom(void *dst, size_t size);

BTC_EXTERN uint32_t
btc_random(void);

BTC_EXTERN uint32_t
btc_uniform(uint32_t max);

BTC_EXTERN void
btc_ecdsa_privkey_generate(uint8_t *out);

BTC_EXTERN int
btc_ecdsa_privkey_verify(const uint8_t *priv);

BTC_EXTERN int
btc_ecdsa_privkey_tweak_add(uint8_t *out,
                            const uint8_t *priv,
                            const uint8_t *tweak);

BTC_EXTERN int
btc_ecdsa_pubkey_create(uint8_t *pub,
                        const uint8_t *priv,
                        int compact);

BTC_EXTERN int
btc_ecdsa_pubkey_convert(uint8_t *out,
                         const uint8_t *pub,
                         size_t pub_len,
                         int compact);

BTC_EXTERN int
btc_ecdsa_pubkey_verify(const uint8_t *pub, size_t pub_len);

BTC_EXTERN int
btc_ecdsa_pubkey_tweak_add(uint8_t *out,
                           const uint8_t *pub,
                           size_t pub_len,
                           const uint8_t *tweak,
                           int compact);

BTC_EXTERN int
btc_ecdsa_is_low_der(const uint8_t *der, size_t der_len);

BTC_EXTERN int
btc_ecdsa_sign(uint8_t *der,
               size_t *der_len,
               const uint8_t *msg,
               const uint8_t *priv);

BTC_EXTERN int
btc_ecdsa_verify(const uint8_t *msg,
                 const uint8_t *der,
                 size_t der_len,
                 const uint8_t *pub,
                 size_t pub_len);

BTC_EXTERN int
btc_ecdsa_checksig(const uint8_t *msg,
                   const uint8_t *der,
                   size_t der_len,
                   const uint8_t *pub,
                   size_t pub_len);

BTC_EXTERN void
btc_bip340_privkey_generate(uint8_t *out, const uint8_t *entropy);

BTC_EXTERN int
btc_bip340_privkey_verify(const uint8_t *priv);

BTC_EXTERN int
btc_bip340_privkey_tweak_add(uint8_t *out,
                             const uint8_t *priv,
                             const uint8_t *tweak);

BTC_EXTERN int
btc_bip340_pubkey_create(uint8_t *pub, const uint8_t *priv);

BTC_EXTERN int
btc_bip340_pubkey_verify(const uint8_t *pub);

BTC_EXTERN int
btc_bip340_pubkey_tweak_add(uint8_t *out,
                            int *negated,
                            const uint8_t *pub,
                            const uint8_t *tweak);

BTC_EXTERN int
btc_bip340_pubkey_tweak_add_check(const uint8_t *pub,
                                  const uint8_t *tweak,
                                  const uint8_t *expect,
                                  int negated);

BTC_EXTERN int
btc_bip340_sign(uint8_t *sig, const uint8_t *msg, const uint8_t *priv);

BTC_EXTERN int
btc_bip340_verify(const uint8_t *msg, const uint8_t *sig, const uint8_t *pub);

BTC_EXTERN int
btc_merkle_root(uint8_t *root, uint8_t *nodes, size_t size);

#endif /* BTC_CRYPTO_H */
