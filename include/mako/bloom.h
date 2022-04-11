/*!
 * bloom.h - bloom filters for mako
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifndef BTC_BLOOM_H
#define BTC_BLOOM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "common.h"
#include "impl.h"
#include "types.h"

/*
 * Constants
 */

/**
 * Max bloom filter size.
 */

#define BTC_BLOOM_MAX_BLOOM_FILTER_SIZE 36000

/**
 * Max number of hash functions.
 */

#define BTC_BLOOM_MAX_HASH_FUNCS 50

/**
 * Bloom filter update flags.
 */

enum btc_bloom_flag {
  /**
   * Never update the filter with outpoints.
   */

  BTC_BLOOM_NONE = 0,

  /**
   * Always update the filter with outpoints.
   */

  BTC_BLOOM_ALL = 1,

  /**
   * Only update the filter with outpoints if it is
   * "asymmetric" in terms of addresses (pubkey/multisig).
   */

  BTC_BLOOM_PUBKEY_ONLY = 2,

  /**
   * Mask for the above flags.
   */

  BTC_BLOOM_MASK = 3,

  /**
   * No updates. Internal usage.
   */

  BTC_BLOOM_INTERNAL = BTC_BLOOM_ALL | (1 << 7)
};

/*
 * Bloom Filter
 */

BTC_DEFINE_SERIALIZABLE_OBJECT(btc_bloom, BTC_SCOPE_EXTERN)

BTC_EXTERN void
btc_bloom_init(btc_bloom_t *bloom);

BTC_EXTERN void
btc_bloom_clear(btc_bloom_t *bloom);

BTC_EXTERN void
btc_bloom_copy(btc_bloom_t *z, const btc_bloom_t *x);

BTC_EXTERN void
btc_bloom_reset(btc_bloom_t *bloom);

BTC_EXTERN void
btc_bloom_set(btc_bloom_t *bloom,
              uint32_t items,
              double rate,
              uint8_t update);

BTC_EXTERN void
btc_bloom_add(btc_bloom_t *bloom, const uint8_t *val, size_t len);

BTC_EXTERN int
btc_bloom_has(const btc_bloom_t *bloom, const uint8_t *val, size_t len);

BTC_EXTERN int
btc_bloom_is_within_constraints(const btc_bloom_t *bloom);

BTC_EXTERN size_t
btc_bloom_size(const btc_bloom_t *x);

BTC_EXTERN uint8_t *
btc_bloom_write(uint8_t *zp, const btc_bloom_t *x);

BTC_EXTERN int
btc_bloom_read(btc_bloom_t *z, const uint8_t **xp, size_t *xn);

/*
 * Rolling Filter
 */

BTC_DEFINE_OBJECT(btc_filter, BTC_SCOPE_EXTERN)

BTC_EXTERN void
btc_filter_init(btc_filter_t *filter);

BTC_EXTERN void
btc_filter_clear(btc_filter_t *filter);

BTC_EXTERN void
btc_filter_copy(btc_filter_t *z, const btc_filter_t *x);

BTC_EXTERN void
btc_filter_reset(btc_filter_t *filter);

BTC_EXTERN void
btc_filter_set(btc_filter_t *filter, uint32_t items, double rate);

BTC_EXTERN void
btc_filter_add(btc_filter_t *filter, const uint8_t *val, size_t len);

BTC_EXTERN int
btc_filter_has(const btc_filter_t *filter, const uint8_t *val, size_t len);

BTC_EXTERN void
btc_filter_add_addr(btc_filter_t *filter, const btc_netaddr_t *addr);

BTC_EXTERN int
btc_filter_has_addr(const btc_filter_t *filter, const btc_netaddr_t *addr);

#ifdef __cplusplus
}
#endif

#endif /* BTC_BLOOM_H */
