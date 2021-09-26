/*!
 * map.h - map for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef BTC_MAP_INTERNAL_H
#define BTC_MAP_INTERNAL_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <satoshi/util.h>
#include "../internal.h"

#define MAP_STATIC BTC_UNUSED static
#define MAP_EXTERN

#ifndef BTC_MAP_INTERNAL_OLD_H
#define BTC_MAP_INTERNAL_OLD_H

#define kh_inline BTC_INLINE
#define kh_unused BTC_UNUSED

#include "khash.h"

#define kh_hash_hash_func(x) btc_murmur3_sum(x, 32, 0xfba4c795)
#define kh_hash_hash_equal(x, y) (memcmp(x, y, 32) == 0)

#define KHASH_SET_INIT_HASH(name)                          \
  KHASH_INIT(name, uint8_t *, char, 0, kh_hash_hash_func,  \
                                       kh_hash_hash_equal)

#define KHASH_MAP_INIT_HASH(name, khval_t)                    \
  KHASH_INIT(name, uint8_t *, khval_t, 1, kh_hash_hash_func,  \
                                          kh_hash_hash_equal)

#define KHASH_SET_INIT_CONST_HASH(name)                          \
  KHASH_INIT(name, const uint8_t *, char, 0, kh_hash_hash_func,  \
                                             kh_hash_hash_equal)

#define KHASH_MAP_INIT_CONST_HASH(name, khval_t)                    \
  KHASH_INIT(name, const uint8_t *, khval_t, 1, kh_hash_hash_func,  \
                                                kh_hash_hash_equal)

#define KHASH_SET_INIT_OUTPOINT(name)                             \
  KHASH_INIT(name, btc_outpoint_t *, char, 0, btc_outpoint_hash,  \
                                              btc_outpoint_equal)

#define KHASH_MAP_INIT_OUTPOINT(name, khval_t)                       \
  KHASH_INIT(name, btc_outpoint_t *, khval_t, 1, btc_outpoint_hash,  \
                                                 btc_outpoint_equal)

#define KHASH_SET_INIT_CONST_OUTPOINT(name)                             \
  KHASH_INIT(name, const btc_outpoint_t *, char, 0, btc_outpoint_hash,  \
                                                    btc_outpoint_equal)

#define KHASH_MAP_INIT_CONST_OUTPOINT(name, khval_t)                       \
  KHASH_INIT(name, const btc_outpoint_t *, khval_t, 1, btc_outpoint_hash,  \
                                                       btc_outpoint_equal)

#define KHASH_SET_INIT_NETADDR(name)                            \
  KHASH_INIT(name, btc_netaddr_t *, char, 0, btc_netaddr_hash,  \
                                             btc_netaddr_equal)

#define KHASH_MAP_INIT_NETADDR(name, khval_t)                      \
  KHASH_INIT(name, btc_netaddr_t *, khval_t, 1, btc_netaddr_hash,  \
                                                btc_netaddr_equal)

#define KHASH_SET_INIT_CONST_NETADDR(name)                            \
  KHASH_INIT(name, const btc_netaddr_t *, char, 0, btc_netaddr_hash,  \
                                                   btc_netaddr_equal)

#define KHASH_MAP_INIT_CONST_NETADDR(name, khval_t)                      \
  KHASH_INIT(name, const btc_netaddr_t *, khval_t, 1, btc_netaddr_hash,  \
                                                      btc_netaddr_equal)

#endif

/*
 * Map
 */

#define DEFINE_MAP_TYPES(name, keytype, valtype) \
                                                 \
struct kh_##name##_s;                            \
typedef struct kh_##name##_s name##_t;           \
                                                 \
typedef struct name##iter_s {                    \
  struct kh_##name##_s *map;                     \
  unsigned int it;                               \
  keytype key;                                   \
  valtype val;                                   \
} name##iter_t

#define DEFINE_MAP(name, keytype, valtype, hashkey, cmpkey, sentinel, scope) \
                                                                             \
KHASH_INIT(name, keytype, valtype, 1, hashkey, cmpkey)                       \
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
name##_reset(kh_##name##_t *map) {                                           \
  kh_clear_##name(map);                                                      \
}                                                                            \
                                                                             \
scope void                                                                   \
name##_resize(kh_##name##_t *map, size_t size) {                             \
  kh_resize_##name(map, size);                                               \
}                                                                            \
                                                                             \
scope size_t                                                                 \
name##_size(kh_##name##_t *map) {                                            \
  return kh_size(map);                                                       \
}                                                                            \
                                                                             \
scope size_t                                                                 \
name##_buckets(kh_##name##_t *map) {                                         \
  return kh_n_buckets(map);                                                  \
}                                                                            \
                                                                             \
scope int                                                                    \
name##_has(kh_##name##_t *map, const keytype key) {                          \
  khiter_t it = kh_get_##name(map, (keytype)key);                            \
  return it != kh_end(map);                                                  \
}                                                                            \
                                                                             \
scope valtype                                                                \
name##_get(kh_##name##_t *map, const keytype key) {                          \
  khiter_t it = kh_get_##name(map, (keytype)key);                            \
                                                                             \
  if (it == kh_end(map))                                                     \
    return (sentinel);                                                       \
                                                                             \
  return (valtype)kh_value(map, it);                                         \
}                                                                            \
                                                                             \
scope int                                                                    \
name##_put(kh_##name##_t *map, const keytype key, const valtype val) {       \
  int ret = -1;                                                              \
  khiter_t it;                                                               \
                                                                             \
  it = kh_put_##name(map, (keytype)key, &ret);                               \
                                                                             \
  if (ret == -1)                                                             \
    abort(); /* LCOV_EXCL_LINE */                                            \
                                                                             \
  if (ret == 0)                                                              \
    return 0;                                                                \
                                                                             \
  kh_value(map, it) = (valtype)val;                                          \
                                                                             \
  return 1;                                                                  \
}                                                                            \
                                                                             \
scope int                                                                    \
name##_del(kh_##name##_t *map, const keytype key) {                          \
  khiter_t it = kh_get_##name(map, (keytype)key);                            \
                                                                             \
  if (it == kh_end(map))                                                     \
    return 0;                                                                \
                                                                             \
  kh_del_##name(map, it);                                                    \
                                                                             \
  return 1;                                                                  \
}                                                                            \
                                                                             \
scope void                                                                   \
name##_iterate(name##iter_t *iter, kh_##name##_t *map) {                     \
  iter->map = map;                                                           \
  iter->it = kh_begin(map);                                                  \
  iter->key = (keytype)0;                                                    \
  iter->val = (sentinel);                                                    \
}                                                                            \
                                                                             \
scope int                                                                    \
name##_next(name##iter_t *iter) {                                            \
  kh_##name##_t *map = iter->map;                                            \
                                                                             \
  for (; iter->it != kh_end(map); iter->it++) {                              \
    if (kh_exist(map, iter->it)) {                                           \
      iter->key = kh_key(map, iter->it);                                     \
      iter->val = kh_val(map, iter->it);                                     \
      iter->it++;                                                            \
      return 1;                                                              \
    }                                                                        \
  }                                                                          \
                                                                             \
  return 0;                                                                  \
}

/*
 * Set
 */

#define DEFINE_SET_TYPES(name, keytype) \
  DEFINE_MAP_TYPES(name, keytype, int)

#define DEFINE_SET(name, keytype, hashkey, cmpkey, scope)                    \
                                                                             \
KHASH_INIT(name, keytype, char, 0, hashkey, cmpkey)                          \
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
name##_reset(kh_##name##_t *map) {                                           \
  kh_clear_##name(map);                                                      \
}                                                                            \
                                                                             \
scope void                                                                   \
name##_resize(kh_##name##_t *map, size_t size) {                             \
  kh_resize_##name(map, size);                                               \
}                                                                            \
                                                                             \
scope size_t                                                                 \
name##_size(kh_##name##_t *map) {                                            \
  return kh_size(map);                                                       \
}                                                                            \
                                                                             \
scope size_t                                                                 \
name##_buckets(kh_##name##_t *map) {                                         \
  return kh_n_buckets(map);                                                  \
}                                                                            \
                                                                             \
scope int                                                                    \
name##_has(kh_##name##_t *map, const keytype key) {                          \
  khiter_t it = kh_get_##name(map, (keytype)key);                            \
  return it != kh_end(map);                                                  \
}                                                                            \
                                                                             \
scope int                                                                    \
name##_add(kh_##name##_t *map, const keytype key) {                          \
  int ret = -1;                                                              \
                                                                             \
  kh_put_##name(map, (keytype)key, &ret);                                    \
                                                                             \
  if (ret == -1)                                                             \
    abort(); /* LCOV_EXCL_LINE */                                            \
                                                                             \
  return ret > 0;                                                            \
}                                                                            \
                                                                             \
scope int                                                                    \
name##_del(kh_##name##_t *map, const keytype key) {                          \
  khiter_t it = kh_get_##name(map, (keytype)key);                            \
                                                                             \
  if (it == kh_end(map))                                                     \
    return 0;                                                                \
                                                                             \
  kh_del_##name(map, it);                                                    \
                                                                             \
  return 1;                                                                  \
}                                                                            \
                                                                             \
scope void                                                                   \
name##_iterate(name##iter_t *iter, kh_##name##_t *map) {                     \
  iter->map = map;                                                           \
  iter->it = kh_begin(map);                                                  \
  iter->key = (keytype)0;                                                    \
}                                                                            \
                                                                             \
scope int                                                                    \
name##_next(name##iter_t *iter) {                                            \
  kh_##name##_t *map = iter->map;                                            \
                                                                             \
  for (; iter->it != kh_end(map); iter->it++) {                              \
    if (kh_exist(map, iter->it)) {                                           \
      iter->key = kh_key(map, iter->it);                                     \
      iter->it++;                                                            \
      return 1;                                                              \
    }                                                                        \
  }                                                                          \
                                                                             \
  return 0;                                                                  \
}

/*
 * Maps
 */

#define DEFINE_UINT32_MAP(name, valtype, sentinel, scope) \
  DEFINE_MAP(name, uint32_t, valtype, kh_int_hash_func,   \
             kh_int_hash_equal, sentinel, scope)

#define DEFINE_UINT64_MAP(name, valtype, sentinel, scope)  \
  DEFINE_MAP(name, uint64_t, valtype, kh_int64_hash_func,  \
             kh_int64_hash_equal, sentinel, scope)

#define DEFINE_HASH_MAP(name, valtype, sentinel, scope)   \
  DEFINE_MAP(name, uint8_t *, valtype, kh_hash_hash_func, \
             kh_hash_hash_equal, sentinel, scope)

#define DEFINE_OUTPOINT_MAP(name, valtype, sentinel, scope)      \
  DEFINE_MAP(name, btc_outpoint_t *, valtype, btc_outpoint_hash, \
             btc_outpoint_equal, sentinel, scope)

#define DEFINE_NETADDR_MAP(name, valtype, sentinel, scope)     \
  DEFINE_MAP(name, btc_netaddr_t *, valtype, btc_netaddr_hash, \
             btc_netaddr_equal, sentinel, scope)

/*
 * Sets
 */

#define DEFINE_UINT32_SET(name, scope) \
  DEFINE_SET(name, uint32_t, kh_int_hash_func, kh_int_hash_equal, scope)

#define DEFINE_UINT64_SET(name, scope) \
  DEFINE_SET(name, uint64_t, kh_int64_hash_func, kh_int64_hash_equal, scope)

#define DEFINE_HASH_SET(name, scope) \
  DEFINE_SET(name, uint8_t *, kh_hash_hash_func, kh_hash_hash_equal, scope)

#define DEFINE_OUTPOINT_SET(name, scope)                \
  DEFINE_SET(name, btc_outpoint_t *, btc_outpoint_hash, \
             btc_outpoint_equal, scope)

#define DEFINE_NETADDR_SET(name, scope) \
  DEFINE_SET(name, btc_netaddr_t *, btc_netaddr_hash, btc_netaddr_equal, scope)

#endif /* BTC_MAP_INTERNAL_H */
