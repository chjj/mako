/*!
 * ecc.h - elliptic curves for libsatoshi
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef BTC_ECC_INTERNAL_H
#define BTC_ECC_INTERNAL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

#undef BTC_EXTERN
#define BTC_EXTERN

/*
 * Symbol Aliases
 */

#define wei_curve_create btc__wei_curve_create
#define wei_curve_destroy btc__wei_curve_destroy
#define wei_scratch_destroy btc__wei_scratch_destroy
#define wei_curve_scalar_size btc__wei_curve_scalar_size
#define wei_curve_scalar_bits btc__wei_curve_scalar_bits
#define wei_curve_field_size btc__wei_curve_field_size
#define wei_curve_field_bits btc__wei_curve_field_bits
#define wei_curve_randomize btc__wei_curve_randomize
#define wei_scratch_create btc__wei_scratch_create

#define ecdsa_privkey_size btc__ecdsa_privkey_size
#define ecdsa_pubkey_size btc__ecdsa_pubkey_size
#define ecdsa_sig_size btc__ecdsa_sig_size
#define ecdsa_privkey_generate btc__ecdsa_privkey_generate
#define ecdsa_privkey_verify btc__ecdsa_privkey_verify
#define ecdsa_privkey_export btc__ecdsa_privkey_export
#define ecdsa_privkey_import btc__ecdsa_privkey_import
#define ecdsa_privkey_tweak_add btc__ecdsa_privkey_tweak_add
#define ecdsa_privkey_tweak_mul btc__ecdsa_privkey_tweak_mul
#define ecdsa_privkey_negate btc__ecdsa_privkey_negate
#define ecdsa_privkey_invert btc__ecdsa_privkey_invert
#define ecdsa_pubkey_create btc__ecdsa_pubkey_create
#define ecdsa_pubkey_convert btc__ecdsa_pubkey_convert
#define ecdsa_pubkey_from_uniform btc__ecdsa_pubkey_from_uniform
#define ecdsa_pubkey_to_uniform btc__ecdsa_pubkey_to_uniform
#define ecdsa_pubkey_from_hash btc__ecdsa_pubkey_from_hash
#define ecdsa_pubkey_to_hash btc__ecdsa_pubkey_to_hash
#define ecdsa_pubkey_verify btc__ecdsa_pubkey_verify
#define ecdsa_pubkey_export btc__ecdsa_pubkey_export
#define ecdsa_pubkey_import btc__ecdsa_pubkey_import
#define ecdsa_pubkey_tweak_add btc__ecdsa_pubkey_tweak_add
#define ecdsa_pubkey_tweak_mul btc__ecdsa_pubkey_tweak_mul
#define ecdsa_pubkey_add btc__ecdsa_pubkey_add
#define ecdsa_pubkey_combine btc__ecdsa_pubkey_combine
#define ecdsa_pubkey_negate btc__ecdsa_pubkey_negate
#define ecdsa_sig_export btc__ecdsa_sig_export
#define ecdsa_sig_import_lax btc__ecdsa_sig_import_lax
#define ecdsa_sig_import btc__ecdsa_sig_import
#define ecdsa_sig_normalize btc__ecdsa_sig_normalize
#define ecdsa_is_low_s btc__ecdsa_is_low_s
#define ecdsa_sign btc__ecdsa_sign
#define ecdsa_sign_internal btc__ecdsa_sign_internal
#define ecdsa_verify btc__ecdsa_verify
#define ecdsa_recover btc__ecdsa_recover
#define ecdsa_derive btc__ecdsa_derive

#define bip340_privkey_size btc__bip340_privkey_size
#define bip340_pubkey_size btc__bip340_pubkey_size
#define bip340_sig_size btc__bip340_sig_size
#define bip340_privkey_generate btc__bip340_privkey_generate
#define bip340_privkey_verify btc__bip340_privkey_verify
#define bip340_privkey_export btc__bip340_privkey_export
#define bip340_privkey_import btc__bip340_privkey_import
#define bip340_privkey_tweak_add btc__bip340_privkey_tweak_add
#define bip340_privkey_tweak_mul btc__bip340_privkey_tweak_mul
#define bip340_privkey_invert btc__bip340_privkey_invert
#define bip340_pubkey_create btc__bip340_pubkey_create
#define bip340_pubkey_from_uniform btc__bip340_pubkey_from_uniform
#define bip340_pubkey_to_uniform btc__bip340_pubkey_to_uniform
#define bip340_pubkey_from_hash btc__bip340_pubkey_from_hash
#define bip340_pubkey_to_hash btc__bip340_pubkey_to_hash
#define bip340_pubkey_verify btc__bip340_pubkey_verify
#define bip340_pubkey_export btc__bip340_pubkey_export
#define bip340_pubkey_import btc__bip340_pubkey_import
#define bip340_pubkey_tweak_add btc__bip340_pubkey_tweak_add
#define bip340_pubkey_tweak_add_check btc__bip340_pubkey_tweak_add_check
#define bip340_pubkey_tweak_mul btc__bip340_pubkey_tweak_mul
#define bip340_pubkey_tweak_mul_check btc__bip340_pubkey_tweak_mul_check
#define bip340_pubkey_add btc__bip340_pubkey_add
#define bip340_pubkey_combine btc__bip340_pubkey_combine
#define bip340_sign btc__bip340_sign
#define bip340_verify btc__bip340_verify
#define bip340_verify_batch btc__bip340_verify_batch
#define bip340_derive btc__bip340_derive

/*
 * Definitions
 */

#define WEI_MAX_FIELD_SIZE 32
#define WEI_MAX_SCALAR_SIZE 32

#define ECDSA_MAX_PRIV_SIZE WEI_MAX_SCALAR_SIZE /* 66 */
#define ECDSA_MAX_PUB_SIZE (1 + WEI_MAX_FIELD_SIZE * 2) /* 133 */
#define ECDSA_MAX_SIG_SIZE (WEI_MAX_SCALAR_SIZE * 2) /* 132 */
#define ECDSA_MAX_DER_SIZE (9 + ECDSA_MAX_SIG_SIZE) /* 141 */

#define BIP340_MAX_PRIV_SIZE WEI_MAX_SCALAR_SIZE /* 66 */
#define BIP340_MAX_PUB_SIZE WEI_MAX_FIELD_SIZE /* 66 */
#define BIP340_MAX_SIG_SIZE \
  (WEI_MAX_FIELD_SIZE + WEI_MAX_SCALAR_SIZE) /* 132 */

/*
 * Curves
 */

typedef enum wei_curve_id {
  WEI_CURVE_SECP256K1
} wei_curve_id_t;

/*
 * Types
 */

typedef struct wei_s wei_curve_t;
typedef struct wei_scratch_s wei_scratch_t;

typedef void ecdsa_redefine_f(void *, size_t);

/*
 * Short Weierstrass Curve
 */

BTC_EXTERN wei_curve_t *
wei_curve_create(wei_curve_id_t type);

BTC_EXTERN void
wei_curve_destroy(wei_curve_t *ec);

BTC_EXTERN void
wei_curve_randomize(wei_curve_t *ec, const unsigned char *entropy);

BTC_EXTERN size_t
wei_curve_scalar_size(const wei_curve_t *ec);

BTC_EXTERN unsigned int
wei_curve_scalar_bits(const wei_curve_t *ec);

BTC_EXTERN size_t
wei_curve_field_size(const wei_curve_t *ec);

BTC_EXTERN unsigned int
wei_curve_field_bits(const wei_curve_t *ec);

BTC_EXTERN wei_scratch_t *
wei_scratch_create(const wei_curve_t *ec, size_t size);

BTC_EXTERN void
wei_scratch_destroy(const wei_curve_t *ec, wei_scratch_t *scratch);

/*
 * ECDSA
 */

BTC_EXTERN size_t
ecdsa_privkey_size(const wei_curve_t *ec);

BTC_EXTERN size_t
ecdsa_pubkey_size(const wei_curve_t *ec, int compact);

BTC_EXTERN size_t
ecdsa_sig_size(const wei_curve_t *ec);

BTC_EXTERN void
ecdsa_privkey_generate(const wei_curve_t *ec,
                       unsigned char *out,
                       const unsigned char *entropy);

BTC_EXTERN int
ecdsa_privkey_verify(const wei_curve_t *ec, const unsigned char *priv);

BTC_EXTERN int
ecdsa_privkey_export(const wei_curve_t *ec,
                     unsigned char *out,
                     const unsigned char *priv);

BTC_EXTERN int
ecdsa_privkey_import(const wei_curve_t *ec,
                     unsigned char *out,
                     const unsigned char *bytes,
                     size_t len);

BTC_EXTERN int
ecdsa_privkey_tweak_add(const wei_curve_t *ec,
                        unsigned char *out,
                        const unsigned char *priv,
                        const unsigned char *tweak);

BTC_EXTERN int
ecdsa_privkey_tweak_mul(const wei_curve_t *ec,
                        unsigned char *out,
                        const unsigned char *priv,
                        const unsigned char *tweak);

BTC_EXTERN int
ecdsa_privkey_negate(const wei_curve_t *ec,
                     unsigned char *out,
                     const unsigned char *priv);

BTC_EXTERN int
ecdsa_privkey_invert(const wei_curve_t *ec,
                     unsigned char *out,
                     const unsigned char *priv);

BTC_EXTERN int
ecdsa_pubkey_create(const wei_curve_t *ec,
                    unsigned char *pub,
                    size_t *pub_len,
                    const unsigned char *priv,
                    int compact);

BTC_EXTERN int
ecdsa_pubkey_convert(const wei_curve_t *ec,
                     unsigned char *out,
                     size_t *out_len,
                     const unsigned char *pub,
                     size_t pub_len,
                     int compact);

BTC_EXTERN void
ecdsa_pubkey_from_uniform(const wei_curve_t *ec,
                          unsigned char *out,
                          size_t *out_len,
                          const unsigned char *bytes,
                          int compact);

BTC_EXTERN int
ecdsa_pubkey_to_uniform(const wei_curve_t *ec,
                        unsigned char *out,
                        const unsigned char *pub,
                        size_t pub_len,
                        unsigned int hint);

BTC_EXTERN int
ecdsa_pubkey_from_hash(const wei_curve_t *ec,
                       unsigned char *out,
                       size_t *out_len,
                       const unsigned char *bytes,
                       int compact);

BTC_EXTERN int
ecdsa_pubkey_to_hash(const wei_curve_t *ec,
                     unsigned char *out,
                     const unsigned char *pub,
                     size_t pub_len,
                     const unsigned char *entropy);

BTC_EXTERN int
ecdsa_pubkey_verify(const wei_curve_t *ec,
                    const unsigned char *pub,
                    size_t pub_len);

BTC_EXTERN int
ecdsa_pubkey_export(const wei_curve_t *ec,
                    unsigned char *x_raw,
                    unsigned char *y_raw,
                    const unsigned char *pub,
                    size_t pub_len);

BTC_EXTERN int
ecdsa_pubkey_import(const wei_curve_t *ec,
                    unsigned char *out,
                    size_t *out_len,
                    const unsigned char *x_raw,
                    size_t x_len,
                    const unsigned char *y_raw,
                    size_t y_len,
                    int sign,
                    int compact);

BTC_EXTERN int
ecdsa_pubkey_tweak_add(const wei_curve_t *ec,
                       unsigned char *out,
                       size_t *out_len,
                       const unsigned char *pub,
                       size_t pub_len,
                       const unsigned char *tweak,
                       int compact);

BTC_EXTERN int
ecdsa_pubkey_tweak_mul(const wei_curve_t *ec,
                       unsigned char *out,
                       size_t *out_len,
                       const unsigned char *pub,
                       size_t pub_len,
                       const unsigned char *tweak,
                       int compact);

BTC_EXTERN int
ecdsa_pubkey_add(const wei_curve_t *ec,
                 unsigned char *out,
                 size_t *out_len,
                 const unsigned char *pub1,
                 size_t pub_len1,
                 const unsigned char *pub2,
                 size_t pub_len2,
                 int compact);

BTC_EXTERN int
ecdsa_pubkey_combine(const wei_curve_t *ec,
                     unsigned char *out,
                     size_t *out_len,
                     const unsigned char *const *pubs,
                     const size_t *pub_lens,
                     size_t len,
                     int compact);

BTC_EXTERN int
ecdsa_pubkey_negate(const wei_curve_t *ec,
                    unsigned char *out,
                    size_t *out_len,
                    const unsigned char *pub,
                    size_t pub_len,
                    int compact);

BTC_EXTERN int
ecdsa_sig_export(const wei_curve_t *ec,
                 unsigned char *out,
                 size_t *out_len,
                 const unsigned char *sig);

BTC_EXTERN int
ecdsa_sig_import_lax(const wei_curve_t *ec,
                     unsigned char *out,
                     const unsigned char *der,
                     size_t der_len);

BTC_EXTERN int
ecdsa_sig_import(const wei_curve_t *ec,
                 unsigned char *out,
                 const unsigned char *der,
                 size_t der_len);

BTC_EXTERN int
ecdsa_sig_normalize(const wei_curve_t *ec,
                    unsigned char *out,
                    const unsigned char *sig);

BTC_EXTERN int
ecdsa_is_low_s(const wei_curve_t *ec, const unsigned char *sig);

BTC_EXTERN int
ecdsa_sign(const wei_curve_t *ec,
           unsigned char *sig,
           unsigned int *param,
           const unsigned char *msg,
           size_t msg_len,
           const unsigned char *priv);

BTC_EXTERN int
ecdsa_sign_internal(const wei_curve_t *ec,
                    unsigned char *sig,
                    unsigned int *param,
                    const unsigned char *msg,
                    size_t msg_len,
                    const unsigned char *priv,
                    ecdsa_redefine_f *redefine);

BTC_EXTERN int
ecdsa_verify(const wei_curve_t *ec,
             const unsigned char *msg,
             size_t msg_len,
             const unsigned char *sig,
             const unsigned char *pub,
             size_t pub_len);

BTC_EXTERN int
ecdsa_recover(const wei_curve_t *ec,
              unsigned char *pub,
              size_t *pub_len,
              const unsigned char *msg,
              size_t msg_len,
              const unsigned char *sig,
              unsigned int param,
              int compact);

BTC_EXTERN int
ecdsa_derive(const wei_curve_t *ec,
             unsigned char *secret,
             size_t *secret_len,
             const unsigned char *pub,
             size_t pub_len,
             const unsigned char *priv,
             int compact);

/*
 * BIP340
 */

BTC_EXTERN size_t
bip340_privkey_size(const wei_curve_t *ec);

BTC_EXTERN size_t
bip340_pubkey_size(const wei_curve_t *ec);

BTC_EXTERN size_t
bip340_sig_size(const wei_curve_t *ec);

BTC_EXTERN void
bip340_privkey_generate(const wei_curve_t *ec,
                        unsigned char *out,
                        const unsigned char *entropy);

BTC_EXTERN int
bip340_privkey_verify(const wei_curve_t *ec, const unsigned char *priv);

BTC_EXTERN int
bip340_privkey_export(const wei_curve_t *ec,
                      unsigned char *d_raw,
                      unsigned char *x_raw,
                      unsigned char *y_raw,
                      const unsigned char *priv);

BTC_EXTERN int
bip340_privkey_import(const wei_curve_t *ec,
                      unsigned char *out,
                      const unsigned char *bytes,
                      size_t len);

BTC_EXTERN int
bip340_privkey_tweak_add(const wei_curve_t *ec,
                         unsigned char *out,
                         const unsigned char *priv,
                         const unsigned char *tweak);

BTC_EXTERN int
bip340_privkey_tweak_mul(const wei_curve_t *ec,
                         unsigned char *out,
                         const unsigned char *priv,
                         const unsigned char *tweak);

BTC_EXTERN int
bip340_privkey_invert(const wei_curve_t *ec,
                      unsigned char *out,
                      const unsigned char *priv);

BTC_EXTERN int
bip340_pubkey_create(const wei_curve_t *ec,
                     unsigned char *pub,
                     const unsigned char *priv);

BTC_EXTERN void
bip340_pubkey_from_uniform(const wei_curve_t *ec,
                           unsigned char *out,
                           const unsigned char *bytes);

BTC_EXTERN int
bip340_pubkey_to_uniform(const wei_curve_t *ec,
                         unsigned char *out,
                         const unsigned char *pub,
                         unsigned int hint);

BTC_EXTERN int
bip340_pubkey_from_hash(const wei_curve_t *ec,
                        unsigned char *out,
                        const unsigned char *bytes);

BTC_EXTERN int
bip340_pubkey_to_hash(const wei_curve_t *ec,
                      unsigned char *out,
                      const unsigned char *pub,
                      const unsigned char *entropy);

BTC_EXTERN int
bip340_pubkey_verify(const wei_curve_t *ec, const unsigned char *pub);

BTC_EXTERN int
bip340_pubkey_export(const wei_curve_t *ec,
                     unsigned char *x_raw,
                     unsigned char *y_raw,
                     const unsigned char *pub);

BTC_EXTERN int
bip340_pubkey_import(const wei_curve_t *ec,
                     unsigned char *out,
                     const unsigned char *x_raw,
                     size_t x_len,
                     const unsigned char *y_raw,
                     size_t y_len);

BTC_EXTERN int
bip340_pubkey_tweak_add(const wei_curve_t *ec,
                        unsigned char *out,
                        int *negated,
                        const unsigned char *pub,
                        const unsigned char *tweak);

BTC_EXTERN int
bip340_pubkey_tweak_add_check(const wei_curve_t *ec,
                              const unsigned char *pub,
                              const unsigned char *tweak,
                              const unsigned char *expect,
                              int negated);

BTC_EXTERN int
bip340_pubkey_tweak_mul(const wei_curve_t *ec,
                        unsigned char *out,
                        int *negated,
                        const unsigned char *pub,
                        const unsigned char *tweak);

BTC_EXTERN int
bip340_pubkey_tweak_mul_check(const wei_curve_t *ec,
                              const unsigned char *pub,
                              const unsigned char *tweak,
                              const unsigned char *expect,
                              int negated);

BTC_EXTERN int
bip340_pubkey_add(const wei_curve_t *ec,
                  unsigned char *out,
                  const unsigned char *pub1,
                  const unsigned char *pub2);

BTC_EXTERN int
bip340_pubkey_combine(const wei_curve_t *ec,
                      unsigned char *out,
                      const unsigned char *const *pubs,
                      size_t len);

BTC_EXTERN int
bip340_sign(const wei_curve_t *ec,
            unsigned char *sig,
            const unsigned char *msg,
            size_t msg_len,
            const unsigned char *priv,
            const unsigned char *aux);

BTC_EXTERN int
bip340_verify(const wei_curve_t *ec,
              const unsigned char *msg,
              size_t msg_len,
              const unsigned char *sig,
              const unsigned char *pub);

BTC_EXTERN int
bip340_verify_batch(const wei_curve_t *ec,
                    const unsigned char *const *msgs,
                    const size_t *msg_lens,
                    const unsigned char *const *sigs,
                    const unsigned char *const *pubs,
                    size_t len,
                    wei_scratch_t *scratch);

BTC_EXTERN int
bip340_derive(const wei_curve_t *ec,
              unsigned char *secret,
              const unsigned char *pub,
              const unsigned char *priv);

#ifdef __cplusplus
}
#endif

#endif /* BTC_ECC_INTERNAL_H */
