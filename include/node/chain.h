/*!
 * chain.h - chain for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef BTC_CHAIN_H
#define BTC_CHAIN_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include "types.h"
#include "../satoshi/common.h"
#include "../satoshi/types.h"

/*
 * Constants
 */

enum btc_chain_flags {
  BTC_CHAIN_VERIFY_NONE = 0,
  BTC_CHAIN_VERIFY_POW  = 1 << 0,
  BTC_CHAIN_VERIFY_BODY = 1 << 1,
  BTC_CHAIN_DEFAULT_FLAGS = BTC_CHAIN_VERIFY_POW | BTC_CHAIN_VERIFY_BODY
};

enum btc_lock_flags {
  BTC_CHAIN_VERIFY_SEQUENCE  = 1 << 0,
  BTC_CHAIN_MEDIAN_TIME_PAST = 1 << 1,
  BTC_CHAIN_MANDATORY_LOCKTIME_FLAGS = 0,
  BTC_CHAIN_STANDARD_LOCKTIME_FLAGS = BTC_CHAIN_VERIFY_SEQUENCE
                                    | BTC_CHAIN_MEDIAN_TIME_PAST
};

enum btc_threshold_state {
  BTC_CHAIN_DEFINED,
  BTC_CHAIN_STARTED,
  BTC_CHAIN_LOCKED_IN,
  BTC_CHAIN_ACTIVE,
  BTC_CHAIN_FAILED
};

/*
 * Types
 */

typedef void btc_chain_block_cb(const btc_block_t *block,
                                const btc_entry_t *entry,
                                void *arg);

typedef void btc_chain_connect_cb(const btc_entry_t *entry,
                                  const btc_block_t *block,
                                  const btc_view_t *view,
                                  void *arg);

typedef void btc_chain_reorganize_cb(const btc_entry_t *old,
                                     const btc_entry_t *new_,
                                     void *arg);

typedef void btc_chain_badorphan_cb(const btc_verify_error_t *err,
                                    unsigned int id,
                                    void *arg);

/*
 * Chain
 */

BTC_EXTERN btc_chain_t *
btc_chain_create(const btc_network_t *network);

BTC_EXTERN void
btc_chain_destroy(btc_chain_t *chain);

BTC_EXTERN void
btc_chain_set_logger(btc_chain_t *chain, btc_logger_t *logger);

BTC_EXTERN void
btc_chain_set_timedata(btc_chain_t *chain, const btc_timedata_t *td);

BTC_EXTERN void
btc_chain_on_block(btc_chain_t *chain, btc_chain_block_cb *handler);

BTC_EXTERN void
btc_chain_on_connect(btc_chain_t *chain, btc_chain_connect_cb *handler);

BTC_EXTERN void
btc_chain_on_disconnect(btc_chain_t *chain, btc_chain_connect_cb *handler);

BTC_EXTERN void
btc_chain_on_reorganize(btc_chain_t *chain, btc_chain_reorganize_cb *handler);

BTC_EXTERN void
btc_chain_on_badorphan(btc_chain_t *chain, btc_chain_badorphan_cb *handler);

BTC_EXTERN void
btc_chain_set_context(btc_chain_t *chain, void *arg);

BTC_EXTERN void
btc_chain_set_checkpoints(btc_chain_t *chain, int value);

BTC_EXTERN int
btc_chain_open(btc_chain_t *chain, const char *prefix, size_t map_size);

BTC_EXTERN void
btc_chain_close(btc_chain_t *chain);

BTC_EXTERN int
btc_chain_has_orphan(btc_chain_t *chain, const uint8_t *hash);

BTC_EXTERN int
btc_chain_has_invalid(btc_chain_t *chain, const uint8_t *hash);

BTC_EXTERN uint32_t
btc_chain_get_target(btc_chain_t *chain,
                     int64_t time,
                     const btc_entry_t *prev);

BTC_EXTERN uint32_t
btc_chain_get_current_target(btc_chain_t *chain);

BTC_EXTERN void
btc_chain_get_deployments(btc_chain_t *chain,
                          btc_deployment_state_t *state,
                          int64_t time,
                          const btc_entry_t *prev);

BTC_EXTERN int
btc_chain_verify_final(btc_chain_t *chain,
                       const btc_entry_t *prev,
                       const btc_tx_t *tx,
                       unsigned int flags);

BTC_EXTERN int
btc_chain_verify_locks(btc_chain_t *chain,
                       const btc_entry_t *prev,
                       const btc_tx_t *tx,
                       const btc_view_t *view,
                       unsigned int flags);

BTC_EXTERN int
btc_chain_add(btc_chain_t *chain,
              const btc_block_t *block,
              unsigned int flags,
              unsigned int id);

BTC_EXTERN const btc_entry_t *
btc_chain_tip(btc_chain_t *chain);

BTC_EXTERN int32_t
btc_chain_height(btc_chain_t *chain);

BTC_EXTERN const btc_deployment_state_t *
btc_chain_state(btc_chain_t *chain);

BTC_EXTERN const btc_verify_error_t *
btc_chain_error(btc_chain_t *chain);

BTC_EXTERN double
btc_chain_progress(btc_chain_t *chain);

BTC_EXTERN int
btc_chain_synced(btc_chain_t *chain);

BTC_EXTERN int
btc_chain_has_hash(btc_chain_t *chain, const uint8_t *hash);

BTC_EXTERN const btc_entry_t *
btc_chain_by_hash(btc_chain_t *chain, const uint8_t *hash);

BTC_EXTERN const btc_entry_t *
btc_chain_by_height(btc_chain_t *chain, int32_t height);

BTC_EXTERN int
btc_chain_is_main(btc_chain_t *chain, const btc_entry_t *entry);

BTC_EXTERN int
btc_chain_has_coins(btc_chain_t *chain, const btc_tx_t *tx);

BTC_EXTERN int
btc_chain_get_coins(btc_chain_t *chain,
                    btc_view_t *view,
                    const btc_tx_t *tx);

BTC_EXTERN btc_block_t *
btc_chain_get_block(btc_chain_t *chain, const btc_entry_t *entry);

BTC_EXTERN int
btc_chain_get_raw_block(btc_chain_t *chain,
                        uint8_t **data,
                        size_t *length,
                        const btc_entry_t *entry);

BTC_EXTERN const uint8_t *
btc_chain_get_orphan_root(btc_chain_t *chain, const uint8_t *hash);

BTC_EXTERN void
btc_chain_get_locator(btc_chain_t *chain,
                      btc_vector_t *hashes,
                      const uint8_t *start);

BTC_EXTERN const btc_entry_t *
btc_chain_find_locator(btc_chain_t *chain, const btc_vector_t *locator);

BTC_EXTERN uint32_t
btc_chain_compute_version(struct btc_chain_s *chain, const btc_entry_t *prev);

#ifdef __cplusplus
}
#endif

#endif /* BTC_CHAIN_H */
