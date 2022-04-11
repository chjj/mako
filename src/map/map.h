/*!
 * map.h - map for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifndef BTC_MAP_INTERNAL_H
#define BTC_MAP_INTERNAL_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <mako/util.h>
#include "../internal.h"

#define MAP_STATIC BTC_UNUSED static
#define MAP_EXTERN extern

#define kh_inline BTC_INLINE
#define kh_unused BTC_UNUSED
#define kfree(x) do { if ((x) != NULL) free(x); } while (0)

#include "khash.h"

#define kh_hash_hash_func(x) btc_murmur3_sum(x, 32, 0xfba4c795)
#define kh_hash_hash_equal(x, y) (memcmp(x, y, 32) == 0)

/*
 * Map
 */

#define DEFINE_MAP_TYPES(name, key_t, val_t) \
typedef struct kh_##name##_s name##_t

#define DEFINE_MAP(name, key_t, val_t, key_hash, key_equal, sentinel, scope) \
                                                                             \
KHASH_INIT(name, key_t, val_t, 1, key_hash, key_equal)                       \
                                                                             \
scope kh_##name##_t *                                                        \
name##_create(void) {                                                        \
  kh_##name##_t *map = kh_init_##name();                                     \
                                                                             \
  if (map == NULL)                                                           \
    abort(); /* LCOV_EXCL_LINE */                                            \
                                                                             \
  return map;                                                                \
}                                                                            \
                                                                             \
scope void                                                                   \
name##_destroy(kh_##name##_t *map) {                                         \
  kh_destroy_##name(map);                                                    \
}                                                                            \
                                                                             \
scope void                                                                   \
name##_init(kh_##name##_t *map) {                                            \
  memset(map, 0, sizeof(kh_##name##_t));                                     \
}                                                                            \
                                                                             \
scope void                                                                   \
name##_clear(kh_##name##_t *map) {                                           \
  kfree((void *)map->keys);                                                  \
  kfree(map->flags);                                                         \
  kfree((void *)map->vals);                                                  \
}                                                                            \
                                                                             \
scope void                                                                   \
name##_reset(kh_##name##_t *map) {                                           \
  kh_clear_##name(map);                                                      \
}                                                                            \
                                                                             \
scope void                                                                   \
name##_resize(kh_##name##_t *map, size_t size) {                             \
  kh_resize_##name(map, size);                                               \
}                                                                            \
                                                                             \
scope btc_mapiter_t                                                          \
name##_lookup(const kh_##name##_t *map, const key_t key) {                   \
  return kh_get_##name(map, (key_t)key);                                     \
}                                                                            \
                                                                             \
scope btc_mapiter_t                                                          \
name##_insert(kh_##name##_t *map, const key_t key, int *exists) {            \
  khiter_t it;                                                               \
  int ret;                                                                   \
                                                                             \
  it = kh_put_##name(map, (key_t)key, &ret);                                 \
                                                                             \
  if (ret < 0)                                                               \
    abort(); /* LCOV_EXCL_LINE */                                            \
                                                                             \
  *exists = (ret == 0);                                                      \
                                                                             \
  return it;                                                                 \
}                                                                            \
                                                                             \
scope void                                                                   \
name##_remove(kh_##name##_t *map, btc_mapiter_t it) {                        \
  kh_del_##name(map, it);                                                    \
}                                                                            \
                                                                             \
scope int                                                                    \
name##_has(const kh_##name##_t *map, const key_t key) {                      \
  khiter_t it = kh_get_##name(map, (key_t)key);                              \
  return it != map->n_buckets;                                               \
}                                                                            \
                                                                             \
scope val_t                                                                  \
name##_get(const kh_##name##_t *map, const key_t key) {                      \
  khiter_t it = kh_get_##name(map, (key_t)key);                              \
                                                                             \
  if (it == map->n_buckets)                                                  \
    return (sentinel);                                                       \
                                                                             \
  return (val_t)map->vals[it];                                               \
}                                                                            \
                                                                             \
scope int                                                                    \
name##_put(kh_##name##_t *map, const key_t key, const val_t val) {           \
  khiter_t it;                                                               \
  int ret;                                                                   \
                                                                             \
  it = kh_put_##name(map, (key_t)key, &ret);                                 \
                                                                             \
  if (ret < 0)                                                               \
    abort(); /* LCOV_EXCL_LINE */                                            \
                                                                             \
  if (ret == 0)                                                              \
    return 0;                                                                \
                                                                             \
  map->vals[it] = (val_t)val;                                                \
                                                                             \
  return 1;                                                                  \
}                                                                            \
                                                                             \
scope key_t                                                                  \
name##_del(kh_##name##_t *map, const key_t key) {                            \
  khiter_t it = kh_get_##name(map, (key_t)key);                              \
  key_t ret;                                                                 \
                                                                             \
  if (it == map->n_buckets)                                                  \
    return (key_t)0;                                                         \
                                                                             \
  ret = map->keys[it];                                                       \
                                                                             \
  kh_del_##name(map, it);                                                    \
                                                                             \
  return ret;                                                                \
}

/*
 * Set
 */

#define DEFINE_SET_TYPES(name, key_t) \
  DEFINE_MAP_TYPES(name, key_t, char)

#define DEFINE_SET(name, key_t, key_hash, key_equal, scope)       \
                                                                  \
KHASH_INIT(name, key_t, char, 0, key_hash, key_equal)             \
                                                                  \
scope kh_##name##_t *                                             \
name##_create(void) {                                             \
  kh_##name##_t *map = kh_init_##name();                          \
                                                                  \
  if (map == NULL)                                                \
    abort(); /* LCOV_EXCL_LINE */                                 \
                                                                  \
  return map;                                                     \
}                                                                 \
                                                                  \
scope void                                                        \
name##_destroy(kh_##name##_t *map) {                              \
  kh_destroy_##name(map);                                         \
}                                                                 \
                                                                  \
scope void                                                        \
name##_init(kh_##name##_t *map) {                                 \
  memset(map, 0, sizeof(kh_##name##_t));                          \
}                                                                 \
                                                                  \
scope void                                                        \
name##_clear(kh_##name##_t *map) {                                \
  kfree((void *)map->keys);                                       \
  kfree(map->flags);                                              \
  kfree((void *)map->vals);                                       \
}                                                                 \
                                                                  \
scope void                                                        \
name##_reset(kh_##name##_t *map) {                                \
  kh_clear_##name(map);                                           \
}                                                                 \
                                                                  \
scope void                                                        \
name##_resize(kh_##name##_t *map, size_t size) {                  \
  kh_resize_##name(map, size);                                    \
}                                                                 \
                                                                  \
scope btc_mapiter_t                                               \
name##_lookup(const kh_##name##_t *map, const key_t key) {        \
  return kh_get_##name(map, (key_t)key);                          \
}                                                                 \
                                                                  \
scope btc_mapiter_t                                               \
name##_insert(kh_##name##_t *map, const key_t key, int *exists) { \
  khiter_t it;                                                    \
  int ret;                                                        \
                                                                  \
  it = kh_put_##name(map, (key_t)key, &ret);                      \
                                                                  \
  if (ret < 0)                                                    \
    abort(); /* LCOV_EXCL_LINE */                                 \
                                                                  \
  *exists = (ret == 0);                                           \
                                                                  \
  return it;                                                      \
}                                                                 \
                                                                  \
scope void                                                        \
name##_remove(kh_##name##_t *map, btc_mapiter_t it) {             \
  kh_del_##name(map, it);                                         \
}                                                                 \
                                                                  \
scope int                                                         \
name##_has(const kh_##name##_t *map, const key_t key) {           \
  khiter_t it = kh_get_##name(map, (key_t)key);                   \
  return it != map->n_buckets;                                    \
}                                                                 \
                                                                  \
scope int                                                         \
name##_put(kh_##name##_t *map, const key_t key) {                 \
  int ret;                                                        \
                                                                  \
  (void)kh_put_##name(map, (key_t)key, &ret);                     \
                                                                  \
  if (ret < 0)                                                    \
    abort(); /* LCOV_EXCL_LINE */                                 \
                                                                  \
  return ret != 0;                                                \
}                                                                 \
                                                                  \
scope key_t                                                       \
name##_del(kh_##name##_t *map, const key_t key) {                 \
  khiter_t it = kh_get_##name(map, (key_t)key);                   \
  key_t ret;                                                      \
                                                                  \
  if (it == map->n_buckets)                                       \
    return (key_t)0;                                              \
                                                                  \
  ret = map->keys[it];                                            \
                                                                  \
  kh_del_##name(map, it);                                         \
                                                                  \
  return ret;                                                     \
}

/*
 * Maps
 */

#define DEFINE_UINT32_MAP(name, val_t, sentinel, scope) \
  DEFINE_MAP(name,                                      \
             uint32_t,                                  \
             val_t,                                     \
             kh_int_hash_func,                          \
             kh_int_hash_equal,                         \
             sentinel,                                  \
             scope)

#define DEFINE_UINT64_MAP(name, val_t, sentinel, scope) \
  DEFINE_MAP(name,                                      \
             uint64_t,                                  \
             val_t,                                     \
             kh_int64_hash_func,                        \
             kh_int64_hash_equal,                       \
             sentinel,                                  \
             scope)

#define DEFINE_HASH_MAP(name, val_t, sentinel, scope) \
  DEFINE_MAP(name,                                    \
             uint8_t *,                               \
             val_t,                                   \
             kh_hash_hash_func,                       \
             kh_hash_hash_equal,                      \
             sentinel,                                \
             scope)

#define DEFINE_OUTPOINT_MAP(name, val_t, sentinel, scope) \
  DEFINE_MAP(name,                                        \
             btc_outpoint_t *,                            \
             val_t,                                       \
             btc_outpoint_hash,                           \
             btc_outpoint_equal,                          \
             sentinel,                                    \
             scope)

#define DEFINE_INVITEM_MAP(name, val_t, sentinel, scope) \
  DEFINE_MAP(name,                                       \
             btc_invitem_t *,                            \
             val_t,                                      \
             btc_invitem_hash,                           \
             btc_invitem_equal,                          \
             sentinel,                                   \
             scope)

#define DEFINE_NETADDR_MAP(name, val_t, sentinel, scope) \
  DEFINE_MAP(name,                                       \
             btc_netaddr_t *,                            \
             val_t,                                      \
             btc_netaddr_hash,                           \
             btc_netaddr_equal,                          \
             sentinel,                                   \
             scope)

#define DEFINE_ADDRESS_MAP(name, val_t, sentinel, scope) \
  DEFINE_MAP(name,                                       \
             btc_address_t *,                            \
             val_t,                                      \
             btc_address_hash,                           \
             btc_address_equal,                          \
             sentinel,                                   \
             scope)

/*
 * Sets
 */

#define DEFINE_UINT32_SET(name, scope) \
  DEFINE_SET(name,                     \
             uint32_t,                 \
             kh_int_hash_func,         \
             kh_int_hash_equal,        \
             scope)

#define DEFINE_UINT64_SET(name, scope) \
  DEFINE_SET(name,                     \
             uint64_t,                 \
             kh_int64_hash_func,       \
             kh_int64_hash_equal,      \
             scope)

#define DEFINE_HASH_SET(name, scope) \
  DEFINE_SET(name,                   \
             uint8_t *,              \
             kh_hash_hash_func,      \
             kh_hash_hash_equal,     \
             scope)

#define DEFINE_OUTPOINT_SET(name, scope) \
  DEFINE_SET(name,                       \
             btc_outpoint_t *,           \
             btc_outpoint_hash,          \
             btc_outpoint_equal,         \
             scope)

#define DEFINE_INVITEM_SET(name, scope) \
  DEFINE_SET(name,                      \
             btc_invitem_t *,           \
             btc_invitem_hash,          \
             btc_invitem_equal,         \
             scope)

#define DEFINE_NETADDR_SET(name, scope) \
  DEFINE_SET(name,                      \
             btc_netaddr_t *,           \
             btc_netaddr_hash,          \
             btc_netaddr_equal,         \
             scope)

#define DEFINE_ADDRESS_SET(name, scope) \
  DEFINE_SET(name,                      \
             btc_address_t *,           \
             btc_address_hash,          \
             btc_address_equal,         \
             scope)

#endif /* BTC_MAP_INTERNAL_H */
