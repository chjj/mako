/*!
 * tx.h - tx for mako
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifndef BTC_TX_H
#define BTC_TX_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "common.h"
#include "impl.h"
#include "types.h"

/*
 * Types
 */

typedef int btc_derive_f(uint8_t *, const btc_address_t *, void *);

/*
 * Outpoint
 */

BTC_DEFINE_SERIALIZABLE_OBJECT(btc_outpoint, BTC_EXTERN)

BTC_EXTERN void
btc_outpoint_init(btc_outpoint_t *z);

BTC_EXTERN void
btc_outpoint_clear(btc_outpoint_t *z);

BTC_EXTERN void
btc_outpoint_copy(btc_outpoint_t *z, const btc_outpoint_t *x);

BTC_EXTERN void
btc_outpoint_set(btc_outpoint_t *z, const uint8_t *hash, uint32_t index);

BTC_EXTERN uint32_t
btc_outpoint_hash(const btc_outpoint_t *x);

BTC_EXTERN int
btc_outpoint_equal(const btc_outpoint_t *x, const btc_outpoint_t *y);

BTC_EXTERN int
btc_outpoint_compare(const btc_outpoint_t *x, const btc_outpoint_t *y);

BTC_EXTERN int
btc_outpoint_is_null(const btc_outpoint_t *x);

BTC_EXTERN size_t
btc_outpoint_size(const btc_outpoint_t *x);

BTC_EXTERN uint8_t *
btc_outpoint_write(uint8_t *zp, const btc_outpoint_t *x);

BTC_EXTERN int
btc_outpoint_read(btc_outpoint_t *z, const uint8_t **xp, size_t *xn);

BTC_EXTERN void
btc_outpoint_update(btc__hash256_t *ctx, const btc_outpoint_t *x);

BTC_EXTERN void
btc_outpoint_inspect(const btc_outpoint_t *outpoint);

/*
 * Input
 */

BTC_DEFINE_SERIALIZABLE_OBJECT(btc_input, BTC_EXTERN)

BTC_EXTERN void
btc_input_init(btc_input_t *z);

BTC_EXTERN void
btc_input_clear(btc_input_t *z);

BTC_EXTERN void
btc_input_copy(btc_input_t *z, const btc_input_t *x);

BTC_EXTERN size_t
btc_input_size(const btc_input_t *x);

BTC_EXTERN uint8_t *
btc_input_write(uint8_t *zp, const btc_input_t *x);

BTC_EXTERN int
btc_input_read(btc_input_t *z, const uint8_t **xp, size_t *xn);

BTC_EXTERN void
btc_input_update(btc__hash256_t *ctx, const btc_input_t *x);

BTC_EXTERN void
btc_input_inspect(const btc_input_t *input,
                  const btc_view_t *view,
                  const btc_network_t *network);

/*
 * Output
 */

BTC_DEFINE_SERIALIZABLE_OBJECT(btc_output, BTC_EXTERN)

BTC_EXTERN void
btc_output_init(btc_output_t *z);

BTC_EXTERN void
btc_output_clear(btc_output_t *z);

BTC_EXTERN void
btc_output_copy(btc_output_t *z, const btc_output_t *x);

BTC_EXTERN int
btc_output_equal(const btc_output_t *x, const btc_output_t *y);

BTC_EXTERN int
btc_output_compare(const btc_output_t *x, const btc_output_t *y);

BTC_EXTERN size_t
btc_output_size(const btc_output_t *x);

BTC_EXTERN uint8_t *
btc_output_write(uint8_t *zp, const btc_output_t *x);

BTC_EXTERN int
btc_output_read(btc_output_t *z, const uint8_t **xp, size_t *xn);

BTC_EXTERN int64_t
btc_output_dust_threshold(const btc_output_t *x, int64_t rate);

BTC_EXTERN int64_t
btc_output_is_dust(const btc_output_t *x, int64_t rate);

BTC_EXTERN void
btc_output_update(btc__hash256_t *ctx, const btc_output_t *x);

BTC_EXTERN size_t
btc_output_deflate(const btc_output_t *x);

BTC_EXTERN uint8_t *
btc_output_compress(uint8_t *zp, const btc_output_t *x);

BTC_EXTERN int
btc_output_decompress(btc_output_t *z, const uint8_t **xp, size_t *xn);

BTC_EXTERN void
btc_output_inspect(const btc_output_t *output, const btc_network_t *network);

/*
 * Input Vector
 */

BTC_DEFINE_HASHABLE_VECTOR(btc_inpvec, btc_input, BTC_EXTERN)

/*
 * Output Vector
 */

BTC_DEFINE_HASHABLE_VECTOR(btc_outvec, btc_output, BTC_EXTERN)

/*
 * Transaction
 */

BTC_DEFINE_SERIALIZABLE_REFOBJ(btc_tx, BTC_EXTERN)

BTC_EXTERN void
btc_tx_init(btc_tx_t *tx);

BTC_EXTERN void
btc_tx_clear(btc_tx_t *tx);

BTC_EXTERN void
btc_tx_copy(btc_tx_t *z, const btc_tx_t *x);

BTC_EXTERN int
btc_tx_is_coinbase(const btc_tx_t *tx);

BTC_EXTERN int
btc_tx_has_witness(const btc_tx_t *tx);

BTC_EXTERN void
btc_tx_txid(uint8_t *hash, const btc_tx_t *tx);

BTC_EXTERN void
btc_tx_wtxid(uint8_t *hash, const btc_tx_t *tx);

BTC_EXTERN void
btc_tx_refresh(btc_tx_t *tx);

BTC_EXTERN void
btc_tx_sighash(uint8_t *hash,
               const btc_tx_t *tx,
               size_t index,
               const btc_script_t *prev,
               int64_t value,
               int type,
               int version,
               btc_tx_cache_t *cache);

BTC_EXTERN int
btc_tx_verify(const btc_tx_t *tx, const btc_view_t *view, unsigned int flags);

BTC_EXTERN int
btc_tx_verify_input(const btc_tx_t *tx,
                    size_t index,
                    const btc_output_t *coin,
                    unsigned int flags,
                    btc_tx_cache_t *cache);

BTC_EXTERN int
btc_tx_is_rbf(const btc_tx_t *tx);

BTC_EXTERN int
btc_tx_is_final(const btc_tx_t *tx, int32_t height, int64_t time);

BTC_EXTERN int
btc_tx_verify_locktime(const btc_tx_t *tx, size_t index, int64_t predicate);

BTC_EXTERN int
btc_tx_verify_sequence(const btc_tx_t *tx, size_t index, int64_t predicate);

BTC_EXTERN int64_t
btc_tx_input_value(const btc_tx_t *tx, const btc_view_t *view);

BTC_EXTERN int64_t
btc_tx_output_value(const btc_tx_t *tx);

BTC_EXTERN int64_t
btc_tx_fee(const btc_tx_t *tx, const btc_view_t *view);

BTC_EXTERN int
btc_tx_legacy_sigops(const btc_tx_t *tx);

BTC_EXTERN int
btc_tx_p2sh_sigops(const btc_tx_t *tx, const btc_view_t *view);

BTC_EXTERN int
btc_tx_witness_sigops(const btc_tx_t *tx, const btc_view_t *view);

BTC_EXTERN int
btc_tx_sigops_cost(const btc_tx_t *tx,
                   const btc_view_t *view,
                   unsigned int flags);

BTC_EXTERN int
btc_tx_sigops(const btc_tx_t *tx, const btc_view_t *view, unsigned int flags);

BTC_EXTERN int
btc_tx_has_duplicate_inputs(const btc_tx_t *tx);

BTC_EXTERN int
btc_tx_check_sanity(btc_verify_error_t *err, const btc_tx_t *tx);

BTC_EXTERN int64_t
btc_tx_check_inputs(btc_verify_error_t *err,
                    const btc_tx_t *tx,
                    const btc_view_t *view,
                    int32_t height);

BTC_EXTERN int
btc_tx_check_standard(btc_verify_error_t *err, const btc_tx_t *tx);

BTC_EXTERN int
btc_tx_has_standard_inputs(const btc_tx_t *tx, const btc_view_t *view);

BTC_EXTERN int
btc_tx_has_standard_witness(const btc_tx_t *tx, const btc_view_t *view);

BTC_EXTERN int
btc_tx_matches(const btc_tx_t *tx, btc_bloom_t *filter);

BTC_EXTERN btc_vector_t *
btc_tx_input_addrs(const btc_tx_t *tx, const btc_view_t *view);

BTC_EXTERN btc_vector_t *
btc_tx_output_addrs(const btc_tx_t *tx);

BTC_EXTERN void
btc_tx_outpoint(btc_outpoint_t *out, const btc_tx_t *tx, uint32_t index);

BTC_EXTERN btc_coin_t *
btc_tx_coin(const btc_tx_t *tx, size_t index, int32_t height);

BTC_EXTERN void
btc_tx_add_input(btc_tx_t *tx, const uint8_t *hash, uint32_t index);

BTC_EXTERN void
btc_tx_add_outpoint(btc_tx_t *tx, const btc_outpoint_t *prevout);

BTC_EXTERN void
btc_tx_add_output(btc_tx_t *tx, const btc_address_t *addr, int64_t value);

BTC_EXTERN void
btc_tx_add_nulldata(btc_tx_t *tx, const uint8_t *data, size_t length);

BTC_EXTERN void
btc_tx_set_locktime(btc_tx_t *tx, uint32_t locktime);

BTC_EXTERN void
btc_tx_set_sequence(btc_tx_t *tx, size_t index, uint32_t locktime, int sec);

BTC_EXTERN void
btc_tx_sort(btc_tx_t *tx);

BTC_EXTERN size_t
btc_tx_base_size(const btc_tx_t *tx);

BTC_EXTERN size_t
btc_tx_witness_size(const btc_tx_t *tx);

BTC_EXTERN size_t
btc_tx_size(const btc_tx_t *tx);

BTC_EXTERN size_t
btc_tx_weight(const btc_tx_t *tx);

BTC_EXTERN size_t
btc_tx_virtual_size(const btc_tx_t *tx);

BTC_EXTERN size_t
btc_tx_sigops_size(const btc_tx_t *tx, int sigops);

BTC_EXTERN uint8_t *
btc_tx_base_write(uint8_t *zp, const btc_tx_t *tx);

BTC_EXTERN uint8_t *
btc_tx_write(uint8_t *zp, const btc_tx_t *tx);

BTC_EXTERN int
btc_tx_read(btc_tx_t *z, const uint8_t **xp, size_t *xn);

BTC_EXTERN void
btc_tx_inspect(const btc_tx_t *tx,
               const btc_view_t *view,
               const btc_network_t *network);

/*
 * Transaction Vector
 */

BTC_DEFINE_SERIALIZABLE_VECTOR(btc_txvec, btc_tx, BTC_EXTERN)

BTC_EXTERN size_t
btc_txvec_base_size(const btc_txvec_t *txs);

BTC_EXTERN uint8_t *
btc_txvec_base_write(uint8_t *zp, const btc_txvec_t *x);

BTC_EXTERN size_t
btc_txvec_witness_size(const btc_txvec_t *txs);

/*
 * Signing
 */

BTC_EXTERN int
btc_tx_sign_step(btc_tx_t *tx,
                 const btc_view_t *view,
                 const uint8_t *priv,
                 btc_tx_cache_t *cache);

BTC_EXTERN int
btc_tx_sign(btc_tx_t *tx,
            const btc_view_t *view,
            btc_derive_f *derive,
            void *arg);

#ifdef __cplusplus
}
#endif

#endif /* BTC_TX_H */
