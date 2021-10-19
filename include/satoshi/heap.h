/*!
 * heap.h - heap functions for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef BTC_HEAP_H
#define BTC_HEAP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "common.h"
#include "types.h"
#include "vector.h"

/*
 * Types
 */

typedef int64_t btc_heapcmp_f(void *x, void *y);

/*
 * Heap
 */

BTC_EXTERN void
btc_heap_init(btc_vector_t *z, btc_heapcmp_f *cmp);

BTC_EXTERN void
btc_heap_insert(btc_vector_t *z, const void *x, btc_heapcmp_f *cmp);

BTC_EXTERN void *
btc_heap_shift(btc_vector_t *z, btc_heapcmp_f *cmp);

BTC_EXTERN void *
btc_heap_remove(btc_vector_t *z, size_t i, btc_heapcmp_f *cmp);

#ifdef __cplusplus
}
#endif

#endif /* BTC_HEAP_H */
