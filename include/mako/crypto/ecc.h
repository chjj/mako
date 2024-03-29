/*!
 * ecc.h - ecc for mako
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifndef BTC_ECC_H
#define BTC_ECC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "../common.h"

/*
 * Types
 */

typedef struct wei_scratch_s btc_scratch_t;
typedef void btc_redefine_f(void *, size_t);

/*
 * Scratch API
 */

BTC_EXTERN btc_scratch_t *
btc_scratch_create(size_t size);

BTC_EXTERN void
btc_scratch_destroy(btc_scratch_t *scratch);

/*
 * ECDSA
 */

BTC_EXTERN void
btc_ecdsa_privkey_generate(unsigned char *out, const unsigned char *entropy);

BTC_EXTERN int
btc_ecdsa_privkey_verify(const unsigned char *priv);

BTC_EXTERN int
btc_ecdsa_privkey_tweak_add(unsigned char *out,
                            const unsigned char *priv,
                            const unsigned char *tweak);

BTC_EXTERN int
btc_ecdsa_privkey_tweak_mul(unsigned char *out,
                            const unsigned char *priv,
                            const unsigned char *tweak);

BTC_EXTERN int
btc_ecdsa_privkey_negate(unsigned char *out, const unsigned char *priv);

BTC_EXTERN int
btc_ecdsa_privkey_invert(unsigned char *out, const unsigned char *priv);

BTC_EXTERN int
btc_ecdsa_pubkey_create(unsigned char *pub,
                        const unsigned char *priv,
                        int compact);

BTC_EXTERN int
btc_ecdsa_pubkey_convert(unsigned char *out,
                         const unsigned char *pub,
                         size_t pub_len,
                         int compact);

BTC_EXTERN void
btc_ecdsa_pubkey_from_uniform(unsigned char *out,
                              const unsigned char *bytes,
                              int compact);

BTC_EXTERN int
btc_ecdsa_pubkey_to_uniform(unsigned char *out,
                            const unsigned char *pub,
                            size_t pub_len,
                            unsigned int hint);

BTC_EXTERN int
btc_ecdsa_pubkey_from_hash(unsigned char *out,
                           const unsigned char *bytes,
                           int compact);

BTC_EXTERN int
btc_ecdsa_pubkey_to_hash(unsigned char *out,
                         const unsigned char *pub,
                         size_t pub_len,
                         const unsigned char *entropy);

BTC_EXTERN int
btc_ecdsa_pubkey_verify(const unsigned char *pub, size_t pub_len);

BTC_EXTERN int
btc_ecdsa_pubkey_tweak_add(unsigned char *out,
                           const unsigned char *pub,
                           size_t pub_len,
                           const unsigned char *tweak,
                           int compact);

BTC_EXTERN int
btc_ecdsa_pubkey_tweak_mul(unsigned char *out,
                           const unsigned char *pub,
                           size_t pub_len,
                           const unsigned char *tweak,
                           int compact);

BTC_EXTERN int
btc_ecdsa_pubkey_add(unsigned char *out,
                     const unsigned char *pub1,
                     size_t pub_len1,
                     const unsigned char *pub2,
                     size_t pub_len2,
                     int compact);

BTC_EXTERN int
btc_ecdsa_pubkey_combine(unsigned char *out,
                         const unsigned char *const *pubs,
                         const size_t *pub_lens,
                         size_t len,
                         int compact);

BTC_EXTERN int
btc_ecdsa_pubkey_negate(unsigned char *out,
                        const unsigned char *pub,
                        size_t pub_len,
                        int compact);

BTC_EXTERN int
btc_ecdsa_sig_export(unsigned char *out,
                     size_t *out_len,
                     const unsigned char *sig);

BTC_EXTERN int
btc_ecdsa_sig_import(unsigned char *out,
                     const unsigned char *der,
                     size_t der_len);

BTC_EXTERN int
btc_ecdsa_sig_import_lax(unsigned char *out,
                         const unsigned char *der,
                         size_t der_len);

BTC_EXTERN int
btc_ecdsa_sig_normalize(unsigned char *out, const unsigned char *sig);

BTC_EXTERN int
btc_ecdsa_is_low_s(const unsigned char *sig);

BTC_EXTERN int
btc_ecdsa_sign(unsigned char *sig,
               unsigned int *param,
               const unsigned char *msg,
               size_t msg_len,
               const unsigned char *priv);

BTC_EXTERN int
btc_ecdsa_sign_internal(unsigned char *sig,
                        unsigned int *param,
                        const unsigned char *msg,
                        size_t msg_len,
                        const unsigned char *priv,
                        btc_redefine_f *redefine);

BTC_EXTERN int
btc_ecdsa_verify(const unsigned char *msg,
                 size_t msg_len,
                 const unsigned char *sig,
                 const unsigned char *pub,
                 size_t pub_len);

BTC_EXTERN int
btc_ecdsa_recover(unsigned char *pub,
                  const unsigned char *msg,
                  size_t msg_len,
                  const unsigned char *sig,
                  unsigned int param,
                  int compact);

BTC_EXTERN int
btc_ecdsa_derive(unsigned char *secret,
                 const unsigned char *pub,
                 size_t pub_len,
                 const unsigned char *priv,
                 int compact);

/*
 * BIP340
 */

BTC_EXTERN void
btc_bip340_privkey_generate(unsigned char *out, const unsigned char *entropy);

BTC_EXTERN int
btc_bip340_privkey_verify(const unsigned char *priv);

BTC_EXTERN int
btc_bip340_privkey_tweak_add(unsigned char *out,
                             const unsigned char *priv,
                             const unsigned char *tweak);

BTC_EXTERN int
btc_bip340_privkey_tweak_mul(unsigned char *out,
                             const unsigned char *priv,
                             const unsigned char *tweak);

BTC_EXTERN int
btc_bip340_privkey_invert(unsigned char *out, const unsigned char *priv);

BTC_EXTERN int
btc_bip340_pubkey_create(unsigned char *pub, const unsigned char *priv);

BTC_EXTERN void
btc_bip340_pubkey_from_uniform(unsigned char *out, const unsigned char *bytes);

BTC_EXTERN int
btc_bip340_pubkey_to_uniform(unsigned char *out,
                             const unsigned char *pub,
                             unsigned int hint);

BTC_EXTERN int
btc_bip340_pubkey_from_hash(unsigned char *out, const unsigned char *bytes);

BTC_EXTERN int
btc_bip340_pubkey_to_hash(unsigned char *out,
                          const unsigned char *pub,
                          const unsigned char *entropy);

BTC_EXTERN int
btc_bip340_pubkey_verify(const unsigned char *pub);

BTC_EXTERN int
btc_bip340_pubkey_tweak_add(unsigned char *out,
                            int *negated,
                            const unsigned char *pub,
                            const unsigned char *tweak);

BTC_EXTERN int
btc_bip340_pubkey_tweak_add_check(const unsigned char *pub,
                                  const unsigned char *tweak,
                                  const unsigned char *expect,
                                  int negated);

BTC_EXTERN int
btc_bip340_pubkey_tweak_mul(unsigned char *out,
                            int *negated,
                            const unsigned char *pub,
                            const unsigned char *tweak);

BTC_EXTERN int
btc_bip340_pubkey_tweak_mul_check(const unsigned char *pub,
                                  const unsigned char *tweak,
                                  const unsigned char *expect,
                                  int negated);

BTC_EXTERN int
btc_bip340_pubkey_add(unsigned char *out,
                      const unsigned char *pub1,
                      const unsigned char *pub2);

BTC_EXTERN int
btc_bip340_pubkey_combine(unsigned char *out,
                          const unsigned char *const *pubs,
                          size_t len);

BTC_EXTERN int
btc_bip340_sign(unsigned char *sig,
                const unsigned char *msg,
                size_t msg_len,
                const unsigned char *priv,
                const unsigned char *aux);

BTC_EXTERN int
btc_bip340_verify(const unsigned char *msg,
                  size_t msg_len,
                  const unsigned char *sig,
                  const unsigned char *pub);

BTC_EXTERN int
btc_bip340_verify_batch(const unsigned char *const *msgs,
                        const size_t *msg_lens,
                        const unsigned char *const *sigs,
                        const unsigned char *const *pubs,
                        size_t len,
                        btc_scratch_t *scratch);

BTC_EXTERN int
btc_bip340_derive(unsigned char *secret,
                  const unsigned char *pub,
                  const unsigned char *priv);

#ifdef __cplusplus
}
#endif

#endif /* BTC_ECC_H */
