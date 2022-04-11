/*!
 * entry.h - entry for mako
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifndef BTC_ENTRY_H
#define BTC_ENTRY_H

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

#define BTC_ENTRY_SIZE 132

/*
 * Chain Entry
 */

BTC_DEFINE_SERIALIZABLE_OBJECT(btc_entry, BTC_SCOPE_EXTERN)

BTC_EXTERN void
btc_entry_init(btc_entry_t *z);

BTC_EXTERN void
btc_entry_clear(btc_entry_t *z);

BTC_EXTERN void
btc_entry_copy(btc_entry_t *z, const btc_entry_t *x);

BTC_EXTERN size_t
btc_entry_size(const btc_entry_t *x);

BTC_EXTERN uint8_t *
btc_entry_write(uint8_t *zp, const btc_entry_t *x);

BTC_EXTERN int
btc_entry_read(btc_entry_t *z, const uint8_t **xp, size_t *xn);

BTC_EXTERN void
btc_entry_set_header(btc_entry_t *entry,
                     const btc_header_t *hdr,
                     const btc_entry_t *prev);

BTC_EXTERN void
btc_entry_set_block(btc_entry_t *entry,
                    const btc_block_t *block,
                    const btc_entry_t *prev);

BTC_EXTERN int64_t
btc_entry_median_time(const btc_entry_t *entry);

BTC_EXTERN void
btc_entry_inspect(const btc_entry_t *entry);

#ifdef __cplusplus
}
#endif

#endif /* BTC_ENTRY_H */
