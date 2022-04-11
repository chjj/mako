/*!
 * map.h - hash tables for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifndef BTC_MAP_H
#define BTC_MAP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "common.h"
#include "types.h"

/*
 * Map
 */

#define BTC_DEFINE_MAP(name, key_t, val_t, scope)            \
                                                             \
scope name##_t *                                             \
name##_create(void);                                         \
                                                             \
scope void                                                   \
name##_destroy(name##_t *map);                               \
                                                             \
scope void                                                   \
name##_init(name##_t *map);                                  \
                                                             \
scope void                                                   \
name##_clear(name##_t *map);                                 \
                                                             \
scope void                                                   \
name##_reset(name##_t *map);                                 \
                                                             \
scope void                                                   \
name##_resize(name##_t *map, size_t size);                   \
                                                             \
scope btc_mapiter_t                                          \
name##_lookup(const name##_t *map, const key_t key);         \
                                                             \
scope btc_mapiter_t                                          \
name##_insert(name##_t *map, const key_t key, int *exists);  \
                                                             \
scope void                                                   \
name##_remove(name##_t *map, btc_mapiter_t it);              \
                                                             \
scope int                                                    \
name##_has(const name##_t *map, const key_t key);            \
                                                             \
scope val_t                                                  \
name##_get(const name##_t *map, const key_t key);            \
                                                             \
scope int                                                    \
name##_put(name##_t *map, const key_t key, const val_t val); \
                                                             \
scope key_t                                                  \
name##_del(name##_t *map, const key_t key)

/*
 * Set
 */

#define BTC_DEFINE_SET(name, key_t, scope)                  \
                                                            \
scope name##_t *                                            \
name##_create(void);                                        \
                                                            \
scope void                                                  \
name##_destroy(name##_t *map);                              \
                                                            \
scope void                                                  \
name##_init(name##_t *map);                                 \
                                                            \
scope void                                                  \
name##_clear(name##_t *map);                                \
                                                            \
scope void                                                  \
name##_reset(name##_t *map);                                \
                                                            \
scope void                                                  \
name##_resize(name##_t *map, size_t size);                  \
                                                            \
scope btc_mapiter_t                                         \
name##_lookup(const name##_t *map, const key_t key);        \
                                                            \
scope btc_mapiter_t                                         \
name##_insert(name##_t *map, const key_t key, int *exists); \
                                                            \
scope void                                                  \
name##_remove(name##_t *map, btc_mapiter_t it);             \
                                                            \
scope int                                                   \
name##_has(const name##_t *map, const key_t key);           \
                                                            \
scope int                                                   \
name##_put(name##_t *map, const key_t key);                 \
                                                            \
scope key_t                                                 \
name##_del(name##_t *map, const key_t key)

/*
 * Maps (Key->Pointer)
 */

BTC_DEFINE_MAP(btc_intmap, uint32_t, void *, BTC_EXTERN);
BTC_DEFINE_MAP(btc_longmap, uint64_t, void *, BTC_EXTERN);
BTC_DEFINE_MAP(btc_hashmap, uint8_t *, void *, BTC_EXTERN);
BTC_DEFINE_MAP(btc_outmap, btc_outpoint_t *, void *, BTC_EXTERN);
/* BTC_DEFINE_MAP(btc_invmap, btc_invitem_t *, void *, BTC_EXTERN); */
BTC_DEFINE_MAP(btc_netmap, btc_netaddr_t *, void *, BTC_EXTERN);
BTC_DEFINE_MAP(btc_addrmap, btc_address_t *, void *, BTC_EXTERN);

/*
 * Tables (Key->Integer)
 */

/* BTC_DEFINE_MAP(btc_inttab, uint32_t, int64_t, BTC_EXTERN); */
BTC_DEFINE_MAP(btc_longtab, uint64_t, int64_t, BTC_EXTERN);
BTC_DEFINE_MAP(btc_hashtab, uint8_t *, int64_t, BTC_EXTERN);
/* BTC_DEFINE_MAP(btc_outtab, btc_outpoint_t *, int64_t, BTC_EXTERN); */
/* BTC_DEFINE_MAP(btc_invtab, btc_invitem_t *, int64_t, BTC_EXTERN); */
/* BTC_DEFINE_MAP(btc_nettab, btc_netaddr_t *, uint64_t, BTC_EXTERN); */
/* BTC_DEFINE_MAP(btc_addrtab, btc_address_t *, uint64_t, BTC_EXTERN); */

/*
 * Sets (Key)
 */

/* BTC_DEFINE_SET(btc_intset, uint32_t, BTC_EXTERN); */
BTC_DEFINE_SET(btc_longset, uint64_t, BTC_EXTERN);
BTC_DEFINE_SET(btc_hashset, uint8_t *, BTC_EXTERN);
BTC_DEFINE_SET(btc_outset, btc_outpoint_t *, BTC_EXTERN);
/* BTC_DEFINE_SET(btc_invset, btc_invitem_t *, BTC_EXTERN); */
/* BTC_DEFINE_SET(btc_netset, btc_netaddr_t *, BTC_EXTERN); */
BTC_DEFINE_SET(btc_addrset, btc_address_t *, BTC_EXTERN);

/*
 * Macros
 */

#define btc_map_exist(map, it) \
  ((((map)->flags[(it) >> 4] >> (((it) & 0x0f) << 1)) & 3) == 0)

#define btc_map_each(map, it)                     \
  for ((it) = 0; (it) < (map)->n_buckets; (it)++) \
    if (btc_map_exist(map, it))

#ifdef __cplusplus
}
#endif

#endif /* BTC_MAP_H */
