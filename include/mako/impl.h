/*!
 * impl.h - internal utils for mako
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifndef BTC_IMPL_H
#define BTC_IMPL_H

#include <stddef.h>
#include <stdint.h>

/*
 * Object
 */

#define BTC_DEFINE_OBJECT(name, scope) \
scope name##_t *                       \
name##_create(void);                   \
                                       \
scope void                             \
name##_destroy(name##_t *z);           \
                                       \
scope name##_t *                       \
name##_clone(const name##_t *x);

/*
 * Ref-Counted Object
 */

#define BTC_DEFINE_REFOBJ(name, scope) \
scope name##_t *                       \
name##_create(void);                   \
                                       \
scope void                             \
name##_destroy(name##_t *z);           \
                                       \
scope name##_t *                       \
name##_clone(const name##_t *x);       \
                                       \
scope name##_t *                       \
name##_ref(name##_t *z);               \
                                       \
scope name##_t *                       \
name##_refconst(const name##_t *x);

/*
 * Vector
 */

#define BTC_DEFINE_VECTOR(name, child, scope) \
BTC_DEFINE_OBJECT(name, scope)                \
                                              \
scope void                                    \
name##_init(name##_t *z);                     \
                                              \
scope void                                    \
name##_clear(name##_t *z);                    \
                                              \
scope void                                    \
name##_reset(name##_t *z);                    \
                                              \
scope void                                    \
name##_grow(name##_t *z, size_t zn);          \
                                              \
scope void                                    \
name##_push(name##_t *z, child##_t *x);       \
                                              \
scope child##_t *                             \
name##_pop(name##_t *z);                      \
                                              \
scope child##_t *                             \
name##_top(const name##_t *z);                \
                                              \
scope void                                    \
name##_drop(name##_t *z);                     \
                                              \
scope void                                    \
name##_resize(name##_t *z, size_t zn);        \
                                              \
scope void                                    \
name##_copy(name##_t *z, const name##_t *x);

/*
 * Serializable (abstract)
 */

#define BTC_DEFINE_SERIALIZABLE(name, scope)                \
scope size_t                                                \
name##_export(uint8_t *zp, const name##_t *x);              \
                                                            \
scope void                                                  \
name##_encode(uint8_t **zp, size_t *zn, const name##_t *x); \
                                                            \
scope int                                                   \
name##_import(name##_t *z, const uint8_t *xp, size_t xn);   \
                                                            \
scope name##_t *                                            \
name##_decode(const uint8_t *xp, size_t xn);

/*
 * Serializable Object
 */

#define BTC_DEFINE_SERIALIZABLE_OBJECT(name, scope) \
BTC_DEFINE_OBJECT(name, scope)                      \
BTC_DEFINE_SERIALIZABLE(name, scope)

/*
 * Serializable Ref-Counted Object
 */

#define BTC_DEFINE_SERIALIZABLE_REFOBJ(name, scope) \
BTC_DEFINE_REFOBJ(name, scope)                      \
BTC_DEFINE_SERIALIZABLE(name, scope)

/*
 * Serializable Vector
 */

#define BTC_DEFINE_SERIALIZABLE_VECTOR(name, child, scope) \
BTC_DEFINE_VECTOR(name, child, scope)                      \
BTC_DEFINE_SERIALIZABLE(name, scope)                       \
                                                           \
scope size_t                                               \
name##_size(const name##_t *x);                            \
                                                           \
scope uint8_t *                                            \
name##_write(uint8_t *zp, const name##_t *x);              \
                                                           \
scope int                                                  \
name##_read(name##_t *z, const uint8_t **xp, size_t *xn);

/*
 * Serializable & Hashable Vector
 */

#define BTC_DEFINE_HASHABLE_VECTOR(name, child, scope) \
BTC_DEFINE_SERIALIZABLE_VECTOR(name, child, scope)     \
                                                       \
scope void                                             \
name##_update(btc__hash256_t *ctx, const name##_t *x);

#endif /* BTC_IMPL_H */
