/*!
 * impl.h - internal utils for mako
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifndef BTC_IMPL_INTERNAL_H
#define BTC_IMPL_INTERNAL_H

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <mako/crypto/hash.h>
#include "internal.h"

/*
 * Scopes
 */

#define SCOPE_STATIC BTC_UNUSED static
#define SCOPE_EXTERN extern

/*
 * Object
 */

#define DEFINE_OBJECT(name, scope)            \
scope void                                    \
name##_init(name##_t *z);                     \
                                              \
scope void                                    \
name##_clear(name##_t *z);                    \
                                              \
scope void                                    \
name##_copy(name##_t *x, const name##_t *y);  \
                                              \
scope name##_t *                              \
name##_create(void) {                         \
  name##_t *z = btc_malloc(sizeof(name##_t)); \
                                              \
  name##_init(z);                             \
                                              \
  return z;                                   \
}                                             \
                                              \
scope void                                    \
name##_destroy(name##_t *z) {                 \
  name##_clear(z);                            \
  btc_free(z);                                \
}                                             \
                                              \
scope name##_t *                              \
name##_clone(const name##_t *x) {             \
  name##_t *z = name##_create();              \
  name##_copy(z, x);                          \
  return z;                                   \
}

/*
 * Ref-Counted Object
 */

#define DEFINE_REFOBJ(name, scope)            \
scope void                                    \
name##_init(name##_t *z);                     \
                                              \
scope void                                    \
name##_clear(name##_t *z);                    \
                                              \
scope void                                    \
name##_copy(name##_t *x, const name##_t *y);  \
                                              \
scope name##_t *                              \
name##_create(void) {                         \
  name##_t *z = btc_malloc(sizeof(name##_t)); \
                                              \
  name##_init(z);                             \
                                              \
  z->_refs = 1;                               \
                                              \
  return z;                                   \
}                                             \
                                              \
scope void                                    \
name##_destroy(name##_t *z) {                 \
  if (z->_refs <= 0)                          \
    btc_abort(); /* LCOV_EXCL_LINE */         \
                                              \
  if (--z->_refs == 0) {                      \
    name##_clear(z);                          \
    btc_free(z);                              \
  }                                           \
}                                             \
                                              \
scope name##_t *                              \
name##_clone(const name##_t *x) {             \
  name##_t *z = name##_create();              \
  name##_copy(z, x);                          \
  return z;                                   \
}                                             \
                                              \
scope name##_t *                              \
name##_ref(name##_t *z) {                     \
  if (z->_refs <= 0)                          \
    btc_abort(); /* LCOV_EXCL_LINE */         \
                                              \
  z->_refs++;                                 \
                                              \
  return z;                                   \
}                                             \
                                              \
name##_t *                                    \
name##_refconst(const name##_t *x) {          \
  if (x->_refs == 0)                          \
    return name##_clone(x);                   \
                                              \
  /* UB if `x` was _defined_ as const! */     \
  return name##_ref((name##_t *)x);           \
}

/*
 * Vector
 */

#define DEFINE_VECTOR(name, child, scope)                       \
DEFINE_OBJECT(name, scope)                                      \
                                                                \
scope void                                                      \
name##_init(name##_t *z) {                                      \
  z->items = NULL;                                              \
  z->alloc = 0;                                                 \
  z->length = 0;                                                \
}                                                               \
                                                                \
scope void                                                      \
name##_clear(name##_t *z) {                                     \
  size_t i;                                                     \
                                                                \
  for (i = 0; i < z->length; i++)                               \
    child##_destroy(z->items[i]);                               \
                                                                \
  if (z->alloc > 0)                                             \
    btc_free(z->items);                                         \
                                                                \
  z->items = NULL;                                              \
  z->alloc = 0;                                                 \
  z->length = 0;                                                \
}                                                               \
                                                                \
scope void                                                      \
name##_reset(name##_t *z) {                                     \
  size_t i;                                                     \
                                                                \
  for (i = 0; i < z->length; i++)                               \
    child##_destroy(z->items[i]);                               \
                                                                \
  z->length = 0;                                                \
}                                                               \
                                                                \
scope void                                                      \
name##_grow(name##_t *z, size_t zn) {                           \
  if (zn > z->alloc) {                                          \
    z->items = btc_realloc(z->items, zn * sizeof(child##_t *)); \
    z->alloc = zn;                                              \
  }                                                             \
}                                                               \
                                                                \
scope void                                                      \
name##_push(name##_t *z, child##_t *x) {                        \
  if (z->length == z->alloc)                                    \
    name##_grow(z, (z->alloc * 3) / 2 + (z->alloc <= 1));       \
                                                                \
  z->items[z->length++] = x;                                    \
}                                                               \
                                                                \
scope child##_t *                                               \
name##_pop(name##_t *z) {                                       \
  CHECK(z->length > 0);                                         \
  return z->items[--z->length];                                 \
}                                                               \
                                                                \
scope child##_t *                                               \
name##_top(const name##_t *z) {                                 \
  CHECK(z->length > 0);                                         \
  return (child##_t *)z->items[z->length - 1];                  \
}                                                               \
                                                                \
scope void                                                      \
name##_drop(name##_t *z) {                                      \
  child##_destroy(name##_pop(z));                               \
}                                                               \
                                                                \
scope void                                                      \
name##_resize(name##_t *z, size_t zn) {                         \
  if (z->length < zn) {                                         \
    name##_grow(z, zn);                                         \
    z->length = zn;                                             \
  } else {                                                      \
    while (z->length > zn)                                      \
      name##_drop(z);                                           \
  }                                                             \
}                                                               \
                                                                \
scope void                                                      \
name##_copy(name##_t *z, const name##_t *x) {                   \
  size_t i;                                                     \
                                                                \
  name##_reset(z);                                              \
  name##_resize(z, x->length);                                  \
                                                                \
  for (i = 0; i < x->length; i++)                               \
    z->items[i] = child##_clone(x->items[i]);                   \
}

/*
 * Serializable (abstract)
 */

#define DEFINE_SERIALIZABLE(name, scope)                     \
scope name##_t *                                             \
name##_create(void);                                         \
                                                             \
scope void                                                   \
name##_destroy(name##_t *z);                                 \
                                                             \
scope size_t                                                 \
name##_size(const name##_t *x);                              \
                                                             \
scope uint8_t *                                              \
name##_write(uint8_t *zp, const name##_t *x);                \
                                                             \
scope int                                                    \
name##_read(name##_t *z, const uint8_t **xp, size_t *xn);    \
                                                             \
scope size_t                                                 \
name##_export(uint8_t *zp, const name##_t *x) {              \
  return name##_write(zp, x) - zp;                           \
}                                                            \
                                                             \
scope void                                                   \
name##_encode(uint8_t **zp, size_t *zn, const name##_t *x) { \
  *zn = name##_size(x);                                      \
  *zp = (uint8_t *)btc_malloc(*zn);                          \
                                                             \
  name##_export(*zp, x);                                     \
}                                                            \
                                                             \
scope int                                                    \
name##_import(name##_t *z, const uint8_t *xp, size_t xn) {   \
  return name##_read(z, &xp, &xn);                           \
}                                                            \
                                                             \
scope name##_t *                                             \
name##_decode(const uint8_t *xp, size_t xn) {                \
  name##_t *z = name##_create();                             \
                                                             \
  if (!name##_import(z, xp, xn)) {                           \
    name##_destroy(z);                                       \
    return NULL;                                             \
  }                                                          \
                                                             \
  return z;                                                  \
}

/*
 * Serializable Object
 */

#define DEFINE_SERIALIZABLE_OBJECT(name, scope) \
DEFINE_OBJECT(name, scope)                      \
DEFINE_SERIALIZABLE(name, scope)

/*
 * Serializable Ref-Counted Object
 */

#define DEFINE_SERIALIZABLE_REFOBJ(name, scope) \
DEFINE_REFOBJ(name, scope)                      \
DEFINE_SERIALIZABLE(name, scope)

/*
 * Serializable Vector
 */

#define DEFINE_SERIALIZABLE_VECTOR(name, child, scope)     \
DEFINE_VECTOR(name, child, scope)                          \
DEFINE_SERIALIZABLE(name, scope)                           \
                                                           \
scope size_t                                               \
name##_size(const name##_t *x) {                           \
  size_t size = 0;                                         \
  size_t i;                                                \
                                                           \
  size += btc_size_size(x->length);                        \
                                                           \
  for (i = 0; i < x->length; i++)                          \
    size += child##_size(x->items[i]);                     \
                                                           \
  return size;                                             \
}                                                          \
                                                           \
scope uint8_t *                                            \
name##_write(uint8_t *zp, const name##_t *x) {             \
  size_t i;                                                \
                                                           \
  zp = btc_size_write(zp, x->length);                      \
                                                           \
  for (i = 0; i < x->length; i++)                          \
    zp = child##_write(zp, x->items[i]);                   \
                                                           \
  return zp;                                               \
}                                                          \
                                                           \
scope int                                                  \
name##_read(name##_t *z, const uint8_t **xp, size_t *xn) { \
  child##_t *item;                                         \
  size_t i, count;                                         \
                                                           \
  name##_reset(z);                                         \
                                                           \
  if (!btc_size_read(&count, xp, xn))                      \
    return 0;                                              \
                                                           \
  for (i = 0; i < count; i++) {                            \
    item = child##_create();                               \
                                                           \
    if (!child##_read(item, xp, xn)) {                     \
      child##_destroy(item);                               \
      return 0;                                            \
    }                                                      \
                                                           \
    name##_push(z, item);                                  \
  }                                                        \
                                                           \
  return 1;                                                \
}

/*
 * Serializable & Hashable Vector
 */

#define DEFINE_HASHABLE_VECTOR(name, child, scope)     \
DEFINE_SERIALIZABLE_VECTOR(name, child, scope)         \
                                                       \
scope void                                             \
name##_update(btc_hash256_t *ctx, const name##_t *x) { \
  size_t i;                                            \
                                                       \
  btc_size_update(ctx, x->length);                     \
                                                       \
  for (i = 0; i < x->length; i++)                      \
    child##_update(ctx, x->items[i]);                  \
}

/*
 * Integral Checks
 */

STATIC_ASSERT(sizeof(uint8_t) == 1);
STATIC_ASSERT(sizeof(uint16_t) == 2);
STATIC_ASSERT(sizeof(uint32_t) == 4);
STATIC_ASSERT(sizeof(uint64_t) == 8);

STATIC_ASSERT(sizeof(int8_t) == 1);
STATIC_ASSERT(sizeof(int16_t) == 2);
STATIC_ASSERT(sizeof(int32_t) == 4);
STATIC_ASSERT(sizeof(int64_t) == 8);

STATIC_ASSERT(sizeof(size_t) >= 4);
STATIC_ASSERT(sizeof(void *) >= 4);

/*
 * Hashing
 */

#define btc_hash256_value(z, x) do {           \
  size_t pos = (z)->size & 63;                 \
                                               \
  if (pos + sizeof(x) >= 64) {                 \
    btc_hash256_update(z, &(x), sizeof(x));    \
  } else {                                     \
    memcpy((z)->block + pos, &(x), sizeof(x)); \
    (z)->size += sizeof(x);                    \
  }                                            \
} while (0)

/*
 * Encoding
 */

BTC_UNUSED static uint8_t *
btc_uint8_write(uint8_t *zp, uint8_t x) {
  *zp++ = x;
  return zp;
}

BTC_UNUSED static int
btc_uint8_read(uint8_t *zp, const uint8_t **xp, size_t *xn) {
  if (*xn < 1)
    return 0;

  *zp = (*xp)[0];
  *xp += 1;
  *xn -= 1;

  return 1;
}

BTC_UNUSED static void
btc_uint8_update(btc_hash256_t *ctx, uint8_t x) {
  size_t pos = ctx->size & 63;

  if (pos == 63) {
    btc_hash256_update(ctx, &x, 1);
  } else {
    ctx->block[pos] = x;
    ctx->size += 1;
  }
}

BTC_UNUSED static uint8_t *
btc_int8_write(uint8_t *zp, int8_t x) {
  return btc_uint8_write(zp, (uint8_t)x);
}

BTC_UNUSED static int
btc_int8_read(int8_t *zp, const uint8_t **xp, size_t *xn) {
  return btc_uint8_read((uint8_t *)zp, xp, xn);
}

BTC_UNUSED static void
btc_int8_update(btc_hash256_t *ctx, int8_t x) {
  btc_uint8_update(ctx, (uint8_t)x);
}

BTC_UNUSED static uint8_t *
btc_uint16_write(uint8_t *zp, uint16_t x) {
#if defined(BTC_BIGENDIAN)
  *zp++ = (x >> 0);
  *zp++ = (x >> 8);
  return zp;
#else
  memcpy(zp, &x, sizeof(x));
  return zp + 2;
#endif
}

BTC_UNUSED static int
btc_uint16_read(uint16_t *zp, const uint8_t **xp, size_t *xn) {
  if (*xn < 2)
    return 0;

#if defined(BTC_BIGENDIAN)
  *zp = ((uint16_t)(*xp)[0] << 0)
      | ((uint16_t)(*xp)[1] << 8);
#else
  memcpy(zp, *xp, sizeof(*zp));
#endif

  *xp += 2;
  *xn -= 2;

  return 1;
}

BTC_UNUSED static void
btc_uint16_update(btc_hash256_t *ctx, uint16_t x) {
#if defined(BTC_BIGENDIAN)
  uint8_t tmp[2];
  btc_uint16_write(tmp, x);
  btc_hash256_update(ctx, tmp, 2);
#else
  btc_hash256_value(ctx, x);
#endif
}

BTC_UNUSED static uint8_t *
btc_int16_write(uint8_t *zp, int16_t x) {
  return btc_uint16_write(zp, (uint16_t)x);
}

BTC_UNUSED static int
btc_int16_read(int16_t *zp, const uint8_t **xp, size_t *xn) {
  return btc_uint16_read((uint16_t *)zp, xp, xn);
}

BTC_UNUSED static void
btc_int16_update(btc_hash256_t *ctx, int16_t x) {
  btc_uint16_update(ctx, (uint16_t)x);
}

BTC_UNUSED static uint8_t *
btc_uint32_write(uint8_t *zp, uint32_t x) {
#if defined(BTC_BIGENDIAN)
  *zp++ = (x >>  0);
  *zp++ = (x >>  8);
  *zp++ = (x >> 16);
  *zp++ = (x >> 24);
  return zp;
#else
  memcpy(zp, &x, sizeof(x));
  return zp + 4;
#endif
}

BTC_UNUSED static int
btc_uint32_read(uint32_t *zp, const uint8_t **xp, size_t *xn) {
  if (*xn < 4)
    return 0;

#if defined(BTC_BIGENDIAN)
  *zp = ((uint32_t)(*xp)[0] <<  0)
      | ((uint32_t)(*xp)[1] <<  8)
      | ((uint32_t)(*xp)[2] << 16)
      | ((uint32_t)(*xp)[3] << 24);
#else
  memcpy(zp, *xp, sizeof(*zp));
#endif

  *xp += 4;
  *xn -= 4;

  return 1;
}

BTC_UNUSED static void
btc_uint32_update(btc_hash256_t *ctx, uint32_t x) {
#if defined(BTC_BIGENDIAN)
  uint8_t tmp[4];
  btc_uint32_write(tmp, x);
  btc_hash256_update(ctx, tmp, 4);
#else
  btc_hash256_value(ctx, x);
#endif
}

BTC_UNUSED static uint8_t *
btc_int32_write(uint8_t *zp, int32_t x) {
  return btc_uint32_write(zp, (uint32_t)x);
}

BTC_UNUSED static int
btc_int32_read(int32_t *zp, const uint8_t **xp, size_t *xn) {
  return btc_uint32_read((uint32_t *)zp, xp, xn);
}

BTC_UNUSED static void
btc_int32_update(btc_hash256_t *ctx, int32_t x) {
  btc_uint32_update(ctx, (uint32_t)x);
}

BTC_UNUSED static uint8_t *
btc_uint64_write(uint8_t *zp, uint64_t x) {
#if defined(BTC_BIGENDIAN)
  *zp++ = (x >>  0);
  *zp++ = (x >>  8);
  *zp++ = (x >> 16);
  *zp++ = (x >> 24);
  *zp++ = (x >> 32);
  *zp++ = (x >> 40);
  *zp++ = (x >> 48);
  *zp++ = (x >> 56);
  return zp;
#else
  memcpy(zp, &x, sizeof(x));
  return zp + 8;
#endif
}

BTC_UNUSED static int
btc_uint64_read(uint64_t *zp, const uint8_t **xp, size_t *xn) {
  if (*xn < 8)
    return 0;

#if defined(BTC_BIGENDIAN)
  *zp = ((uint64_t)(*xp)[0] <<  0)
      | ((uint64_t)(*xp)[1] <<  8)
      | ((uint64_t)(*xp)[2] << 16)
      | ((uint64_t)(*xp)[3] << 24)
      | ((uint64_t)(*xp)[4] << 32)
      | ((uint64_t)(*xp)[5] << 40)
      | ((uint64_t)(*xp)[6] << 48)
      | ((uint64_t)(*xp)[7] << 56);
#else
  memcpy(zp, *xp, sizeof(*zp));
#endif

  *xp += 8;
  *xn -= 8;

  return 1;
}

BTC_UNUSED static void
btc_uint64_update(btc_hash256_t *ctx, uint64_t x) {
#if defined(BTC_BIGENDIAN)
  uint8_t tmp[8];
  btc_uint64_write(tmp, x);
  btc_hash256_update(ctx, tmp, 8);
#else
  btc_hash256_value(ctx, x);
#endif
}

BTC_UNUSED static uint8_t *
btc_int64_write(uint8_t *zp, int64_t x) {
  return btc_uint64_write(zp, (uint64_t)x);
}

BTC_UNUSED static int
btc_int64_read(int64_t *zp, const uint8_t **xp, size_t *xn) {
  return btc_uint64_read((uint64_t *)zp, xp, xn);
}

BTC_UNUSED static void
btc_int64_update(btc_hash256_t *ctx, int64_t x) {
  btc_uint64_update(ctx, (uint64_t)x);
}

BTC_UNUSED static size_t
btc_double_size(double x) {
  return sizeof(x);
}

BTC_UNUSED static uint8_t *
btc_double_write(uint8_t *zp, double x) {
  memcpy(zp, &x, sizeof(x));
  return zp + sizeof(x);
}

BTC_UNUSED static int
btc_double_read(double *zp, const uint8_t **xp, size_t *xn) {
  if (*xn < sizeof(*zp))
    return 0;

  memcpy(zp, *xp, sizeof(*zp));

  *xp += sizeof(*zp);
  *xn -= sizeof(*zp);

  return 1;
}

BTC_UNUSED static void
btc_double_update(btc_hash256_t *ctx, double x) {
  btc_hash256_value(ctx, x);
}

BTC_UNUSED static size_t
btc_compact_size(uint64_t x) {
  if (x < 0xfd)
    return 1;

  if (x <= 0xffff)
    return 3;

  if (x <= 0xffffffff)
    return 5;

  return 9;
}

BTC_UNUSED static uint8_t *
btc_compact_write(uint8_t *zp, uint64_t x) {
  if (x < 0xfd)
    return btc_uint8_write(zp, x);

  if (x <= 0xffff) {
    *zp++ = 0xfd;
    return btc_uint16_write(zp, x);
  }

  if (x <= 0xffffffff) {
    *zp++ = 0xfe;
    return btc_uint32_write(zp, x);
  }

  *zp++ = 0xff;
  return btc_uint64_write(zp, x);
}

BTC_UNUSED static int
btc_compact_read(uint64_t *zp, const uint8_t **xp, size_t *xn) {
  uint8_t type;

  if (!btc_uint8_read(&type, xp, xn))
    return 0;

  switch (type) {
    case 0xff: {
      if (!btc_uint64_read(zp, xp, xn))
        return 0;

      if (*zp <= 0xffffffff)
        return 0;

      break;
    }

    case 0xfe: {
      uint32_t z;

      if (!btc_uint32_read(&z, xp, xn))
        return 0;

      if (z <= 0xffff)
        return 0;

      *zp = z;

      break;
    }

    case 0xfd: {
      uint16_t z;

      if (!btc_uint16_read(&z, xp, xn))
        return 0;

      if (z < 0xfd)
        return 0;

      *zp = z;

      break;
    }

    default: {
      *zp = type;
      break;
    }
  }

  return 1;
}

BTC_UNUSED static void
btc_compact_update(btc_hash256_t *ctx, uint64_t x) {
#if defined(BTC_BIGENDIAN)
  uint8_t tmp[9];
  uint8_t *end = btc_compact_write(tmp, x);

  btc_hash256_update(ctx, tmp, end - tmp);
#else
  if (x < 0xfd) {
    btc_uint8_update(ctx, x);
  } else if (x <= 0xffff) {
    btc_uint8_update(ctx, 0xfd);
    btc_uint16_update(ctx, x);
  } else if (x <= 0xffffffff) {
    btc_uint8_update(ctx, 0xfe);
    btc_uint32_update(ctx, x);
  } else {
    btc_uint8_update(ctx, 0xff);
    btc_uint64_update(ctx, x);
  }
#endif
}

BTC_UNUSED static size_t
btc_size_size(size_t x) {
  return btc_compact_size(x);
}

BTC_UNUSED static uint8_t *
btc_size_write(uint8_t *zp, size_t x) {
  return btc_compact_write(zp, x);
}

BTC_UNUSED static int
btc_size_read(size_t *zp, const uint8_t **xp, size_t *xn) {
  uint64_t z;

  if (!btc_compact_read(&z, xp, xn))
    return 0;

  if (z > 0x02000000)
    return 0;

  *zp = z;

  return 1;
}

BTC_UNUSED static void
btc_size_update(btc_hash256_t *ctx, size_t x) {
  btc_compact_update(ctx, x);
}

BTC_UNUSED static size_t
btc_varint_size(uint64_t x) {
  int n = 0;

  for (;;) {
    n++;

    if (x <= 0x7f)
      break;

    x = (x >> 7) - 1;
  }

  return n;
}

BTC_UNUSED static uint8_t *
btc_varint_write(uint8_t *zp, uint64_t x) {
  uint8_t tmp[(sizeof(x) * 8 + 6) / 7];
  int i = 0;

  for (;;) {
    tmp[i] = (x & 0x7f) | (i ? 0x80 : 0x00);

    if (x <= 0x7f)
      break;

    x = (x >> 7) - 1;
    i++;
  }

  do {
    *zp++ = tmp[i];
  } while (i--);

  return zp;
}

BTC_UNUSED static int
btc_varint_read(uint64_t *zp, const uint8_t **xp, size_t *xn) {
  uint64_t z = 0;
  uint8_t ch;

  for (;;) {
    if (!btc_uint8_read(&ch, xp, xn))
      return 0;

    if (z > (UINT64_MAX >> 7))
      return 0;

    z = (z << 7) | (ch & 0x7f);

    if ((ch & 0x80) == 0)
      break;

    if (z == UINT64_MAX)
      return 0;

    z++;
  }

  *zp = z;

  return 1;
}

BTC_UNUSED static size_t
btc_time_size(int64_t x) {
  (void)x;
  return 4;
}

BTC_UNUSED static uint8_t *
btc_time_write(uint8_t *zp, int64_t x) {
  return btc_uint32_write(zp, (uint32_t)x);
}

BTC_UNUSED static int
btc_time_read(int64_t *zp, const uint8_t **xp, size_t *xn) {
  uint32_t z;

  if (!btc_uint32_read(&z, xp, xn))
    return 0;

  *zp = (int64_t)z;

  return 1;
}

BTC_UNUSED static void
btc_time_update(btc_hash256_t *ctx, int64_t x) {
  btc_uint32_update(ctx, (uint32_t)x);
}

BTC_UNUSED static uint8_t *
btc_raw_write(uint8_t *zp, const uint8_t *xp, size_t xn) {
  if (xn > 0)
    memcpy(zp, xp, xn);

  return zp + xn;
}

BTC_UNUSED static int
btc_raw_read(uint8_t *zp, size_t zn,
            const uint8_t **xp, size_t *xn) {
  if (*xn < zn)
    return 0;

  if (zn > 0) {
    memcpy(zp, *xp, zn);
    *xp += zn;
    *xn -= zn;
  }

  return 1;
}

BTC_UNUSED static int
btc_zraw_read(const uint8_t **zp, size_t zn,
              const uint8_t **xp, size_t *xn) {
  if (*xn < zn)
    return 0;

  *zp = *xp;
  *xp += zn;
  *xn -= zn;

  return 1;
}

BTC_UNUSED static void
btc_raw_update(btc_hash256_t *ctx, const uint8_t *xp, size_t xn) {
  btc_hash256_update(ctx, xp, xn);
}

BTC_UNUSED static size_t
btc_string_size(const char *xp) {
  size_t len = strlen(xp);
  return btc_size_size(len) + len;
}

BTC_UNUSED static uint8_t *
btc_string_write(uint8_t *zp, const char *xp) {
  size_t len = strlen(xp);

  zp = btc_size_write(zp, len);

  if (len > 0)
    memcpy(zp, xp, len);

  return zp + len;
}

BTC_UNUSED static int
btc_string_read(char *zp, size_t zn, const uint8_t **xp, size_t *xn) {
  size_t i, len;

  if (!btc_size_read(&len, xp, xn))
    return 0;

  if (len + 1 > zn)
    return 0;

  if (*xn < len)
    return 0;

  for (i = 0; i < len; i++) {
    int ch = (*xp)[i];

    if (ch < 32 || ch > 126)
      return 0;
  }

  if (len > 0)
    memcpy(zp, *xp, len);

  zp[len] = '\0';

  *xp += len;
  *xn -= len;

  return 1;
}

BTC_UNUSED static void
btc_string_update(btc_hash256_t *ctx, const char *xp) {
  size_t len = strlen(xp);

  btc_size_update(ctx, len);
  btc_hash256_update(ctx, xp, len);
}

BTC_UNUSED static uint8_t *
btc_nullstr_write(uint8_t *zp, const char *xp, size_t xn) {
  size_t len = strlen(xp);

  CHECK(len + 1 <= xn);

  memcpy(zp, xp, len);

  while (len < xn)
    zp[len++] = 0;

  return zp + xn;
}

BTC_UNUSED static int
btc_nullstr_read(char *zp, size_t zn, const uint8_t **xp, size_t *xn) {
  size_t i;

  if (*xn < zn)
    return 0;

  for (i = 0; i < zn; i++) {
    int ch = (*xp)[i];

    if (ch == 0)
      break;

    if (ch < 32 || ch > 126)
      return 0;
  }

  if (i == zn)
    return 0;

  for (; i < zn; i++) {
    int ch = (*xp)[i];

    if (ch != 0)
      return 0;
  }

  memcpy(zp, *xp, zn);

  *xp += zn;
  *xn -= zn;

  return 1;
}

#endif /* BTC_IMPL_INTERNAL_H */
