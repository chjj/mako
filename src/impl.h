/*!
 * impl.h - internal utils for libsatoshi
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef BTC_IMPL_INTERNAL_H
#define BTC_IMPL_INTERNAL_H

#include <stdlib.h>
#include <stdint.h>
#include "internal.h"

struct sha256_s;

void
hash256_update(struct sha256_s *ctx, const void *data, size_t len);

#define SCOPE_STATIC static
#define SCOPE_EXTERN

/*
 * Object
 */

#define DEFINE_OBJECT(name, scope)                          \
scope void                                                  \
name ## _init(name ## _t *z);                               \
                                                            \
scope void                                                  \
name ## _clear(name ## _t *z);                              \
                                                            \
scope void                                                  \
name ## _copy(name ## _t *x, const name ## _t *y);          \
                                                            \
scope name ## _t *                                          \
name ## _create(void) {                                     \
  name ## _t *z = (name ## _t *)malloc(sizeof(name ## _t)); \
                                                            \
  CHECK(z != NULL);                                         \
                                                            \
  name ## _init(z);                                         \
                                                            \
  return z;                                                 \
}                                                           \
                                                            \
scope void                                                  \
name ## _destroy(name ## _t *z) {                           \
  name ## _clear(z);                                        \
  free(z);                                                  \
}                                                           \
                                                            \
scope name ## _t *                                          \
name ## _clone(const name ## _t *x) {                       \
  name ## _t *z = name ## _create();                        \
  name ## _copy(z, x);                                      \
  return z;                                                 \
}

/*
 * Vector
 */

#define DEFINE_VECTOR(name, child, scope)                            \
DEFINE_OBJECT(name, scope)                                           \
                                                                     \
scope void                                                           \
name ## _init(name ## _t *z) {                                       \
  z->items = NULL;                                                   \
  z->alloc = 0;                                                      \
  z->length = 0;                                                     \
}                                                                    \
                                                                     \
scope void                                                           \
name ## _clear(name ## _t *z) {                                      \
  size_t i;                                                          \
                                                                     \
  for (i = 0; i < z->length; i++)                                    \
    child ## _destroy(z->items[i]);                                  \
                                                                     \
  if (z->alloc > 0)                                                  \
    free(z->items);                                                  \
                                                                     \
  z->items = NULL;                                                   \
  z->alloc = 0;                                                      \
  z->length = 0;                                                     \
}                                                                    \
                                                                     \
scope void                                                           \
name ## _reset(name ## _t *z) {                                      \
  size_t i;                                                          \
                                                                     \
  for (i = 0; i < z->length; i++)                                    \
    child ## _destroy(z->items[i]);                                  \
                                                                     \
  z->length = 0;                                                     \
}                                                                    \
                                                                     \
scope void                                                           \
name ## _grow(name ## _t *z, size_t zn) {                            \
  if (zn > z->alloc) {                                               \
    child ## _t **zp =                                               \
      (child ## _t **)realloc(z->items, zn * sizeof(child ## _t *)); \
                                                                     \
    CHECK(zp != NULL);                                               \
                                                                     \
    z->items = zp;                                                   \
    z->alloc = zn;                                                   \
  }                                                                  \
}                                                                    \
                                                                     \
scope void                                                           \
name ## _push(name ## _t *z, child ## _t *x) {                       \
  if (z->length == z->alloc)                                         \
    name ## _grow(z, (z->alloc * 3) / 2 + (z->alloc <= 1));          \
                                                                     \
  z->items[z->length++] = x;                                         \
}                                                                    \
                                                                     \
scope child ## _t *                                                  \
name ## _pop(name ## _t *z) {                                        \
  CHECK(z->length > 0);                                              \
  return z->items[--z->length];                                      \
}                                                                    \
                                                                     \
scope void                                                           \
name ## _drop(name ## _t *z) {                                       \
  child ## _destroy(name ## _pop(z));                                \
}                                                                    \
                                                                     \
scope void                                                           \
name ## _resize(name ## _t *z, size_t zn) {                          \
  if (z->length < zn) {                                              \
    name ## _grow(z, zn);                                            \
    z->length = zn;                                                  \
  } else {                                                           \
    while (z->length > zn)                                           \
      name ## _drop(z);                                              \
  }                                                                  \
}                                                                    \
                                                                     \
scope void                                                           \
name ## _copy(name ## _t *x, const name ## _t *y) {                  \
  size_t i;                                                          \
                                                                     \
  name ## _reset(x);                                                 \
                                                                     \
  for (i = 0; i < y->length; i++)                                    \
    name ## _push(x, child ## _clone(y->items[i]));                  \
}

/*
 * Serializable (abstract)
 */

#define DEFINE_SERIALIZABLE(name, scope)                         \
scope name ## _t *                                               \
name ## _create(void);                                           \
                                                                 \
scope void                                                       \
name ## _destroy(name ## _t *z);                                 \
                                                                 \
scope size_t                                                     \
name ## _size(const name ## _t *x);                              \
                                                                 \
scope uint8_t *                                                  \
name ## _write(uint8_t *zp, const name ## _t *x);                \
                                                                 \
scope int                                                        \
name ## _read(name ## _t *z, const uint8_t **xp, size_t *xn);    \
                                                                 \
scope void                                                       \
name ## _export(uint8_t *zp, const name ## _t *x) {              \
  name ## _write(zp, x);                                         \
}                                                                \
                                                                 \
scope void                                                       \
name ## _encode(uint8_t **zp, size_t *zn, const name ## _t *x) { \
  *zn = name ## _size(x);                                        \
  *zp = (uint8_t *)malloc(*zn);                                  \
                                                                 \
  CHECK(*zp != NULL);                                            \
                                                                 \
  name ## _export(*zp, x);                                       \
}                                                                \
                                                                 \
scope int                                                        \
name ## _import(name ## _t *z, const uint8_t *xp, size_t xn) {   \
  return name ## _read(z, &xp, &xn);                             \
}                                                                \
                                                                 \
scope name ## _t *                                               \
name ## _decode(const uint8_t *xp, size_t xn) {                  \
  name ## _t *z = name ## _create();                             \
                                                                 \
  if (!name ## _import(z, xp, xn)) {                             \
    name ## _destroy(z);                                         \
    return NULL;                                                 \
  }                                                              \
                                                                 \
  return z;                                                      \
}

/*
 * Serializable Object
 */

#define DEFINE_SERIALIZABLE_OBJECT(name, scope) \
DEFINE_OBJECT(name, scope)                      \
DEFINE_SERIALIZABLE(name, scope)

/*
 * Serializable Vector
 */

#define DEFINE_SERIALIZABLE_VECTOR(name, child, scope)         \
DEFINE_VECTOR(name, child, scope)                              \
DEFINE_SERIALIZABLE(name, scope)                               \
                                                               \
scope size_t                                                   \
name ## _size(const name ## _t *x) {                           \
  size_t size = 0;                                             \
  size_t i;                                                    \
                                                               \
  size += btc_size_size(x->length);                            \
                                                               \
  for (i = 0; i < x->length; i++)                              \
    size += child ## _size(x->items[i]);                       \
                                                               \
  return size;                                                 \
}                                                              \
                                                               \
scope uint8_t *                                                \
name ## _write(uint8_t *zp, const name ## _t *x) {             \
  size_t i;                                                    \
                                                               \
  zp = btc_size_write(zp, x->length);                          \
                                                               \
  for (i = 0; i < x->length; i++)                              \
    zp = child ## _write(zp, x->items[i]);                     \
                                                               \
  return zp;                                                   \
}                                                              \
                                                               \
scope int                                                      \
name ## _read(name ## _t *z, const uint8_t **xp, size_t *xn) { \
  child ## _t *item;                                           \
  size_t i, count;                                             \
                                                               \
  if (!btc_size_read(&count, xp, xn))                          \
    return 0;                                                  \
                                                               \
  for (i = 0; i < count; i++) {                                \
    item = child ## _create();                                 \
                                                               \
    if (!child ## _read(item, xp, xn)) {                       \
      child ## _destroy(item);                                 \
      return 0;                                                \
    }                                                          \
                                                               \
    name ## _push(z, item);                                    \
  }                                                            \
                                                               \
  return 1;                                                    \
}                                                              \
                                                               \
scope void                                                     \
name ## _update(struct sha256_s *ctx, const name ## _t *x) {   \
  size_t i;                                                    \
                                                               \
  btc_size_update(ctx, x->length);                             \
                                                               \
  for (i = 0; i < x->length; i++)                              \
    child ## _update(ctx, x->items[i]);                        \
}

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
btc_uint8_update(struct sha256_s *ctx, uint8_t x) {
  hash256_update(ctx, &x, 1);
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
btc_int8_update(struct sha256_s *ctx, int8_t x) {
  btc_uint8_update(ctx, (uint8_t)x);
}

BTC_UNUSED static uint8_t *
btc_uint16_write(uint8_t *zp, uint16_t x) {
  *zp++ = (x >> 0);
  *zp++ = (x >> 8);
  return zp;
}

BTC_UNUSED static int
btc_uint16_read(uint16_t *zp, const uint8_t **xp, size_t *xn) {
  if (*xn < 2)
    return 0;

  *zp = ((uint16_t)(*xp)[0] <<  0)
      | ((uint16_t)(*xp)[1] <<  8);

  *xp += 2;
  *xn -= 2;

  return 1;
}

BTC_UNUSED static void
btc_uint16_update(struct sha256_s *ctx, uint16_t x) {
  uint8_t tmp[2];
  btc_uint16_write(tmp, x);
  hash256_update(ctx, tmp, 2);
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
btc_int16_update(struct sha256_s *ctx, int16_t x) {
  btc_uint16_update(ctx, (uint16_t)x);
}

BTC_UNUSED static uint8_t *
btc_uint32_write(uint8_t *zp, uint32_t x) {
  *zp++ = (x >>  0);
  *zp++ = (x >>  8);
  *zp++ = (x >> 16);
  *zp++ = (x >> 24);
  return zp;
}

BTC_UNUSED static int
btc_uint32_read(uint32_t *zp, const uint8_t **xp, size_t *xn) {
  if (*xn < 4)
    return 0;

  *zp = ((uint32_t)(*xp)[0] <<  0)
      | ((uint32_t)(*xp)[1] <<  8)
      | ((uint32_t)(*xp)[2] << 16)
      | ((uint32_t)(*xp)[3] << 24);

  *xp += 4;
  *xn -= 4;

  return 1;
}

BTC_UNUSED static void
btc_uint32_update(struct sha256_s *ctx, uint32_t x) {
  uint8_t tmp[4];
  btc_uint32_write(tmp, x);
  hash256_update(ctx, tmp, 4);
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
btc_int32_update(struct sha256_s *ctx, int32_t x) {
  btc_uint32_update(ctx, (uint32_t)x);
}

BTC_UNUSED static uint8_t *
btc_uint64_write(uint8_t *zp, uint64_t x) {
  *zp++ = (x >>  0);
  *zp++ = (x >>  8);
  *zp++ = (x >> 16);
  *zp++ = (x >> 24);
  *zp++ = (x >> 32);
  *zp++ = (x >> 40);
  *zp++ = (x >> 48);
  *zp++ = (x >> 56);
  return zp;
}

BTC_UNUSED static int
btc_uint64_read(uint64_t *zp, const uint8_t **xp, size_t *xn) {
  if (*xn < 8)
    return 0;

  *zp = ((uint64_t)(*xp)[0] <<  0)
      | ((uint64_t)(*xp)[1] <<  8)
      | ((uint64_t)(*xp)[2] << 16)
      | ((uint64_t)(*xp)[3] << 24)
      | ((uint64_t)(*xp)[4] << 32)
      | ((uint64_t)(*xp)[5] << 40)
      | ((uint64_t)(*xp)[6] << 48)
      | ((uint64_t)(*xp)[7] << 56);

  *xp += 8;
  *xn -= 8;

  return 1;
}

BTC_UNUSED static void
btc_uint64_update(struct sha256_s *ctx, uint64_t x) {
  uint8_t tmp[8];
  btc_uint64_write(tmp, x);
  hash256_update(ctx, tmp, 8);
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
btc_int64_update(struct sha256_s *ctx, int64_t x) {
  btc_uint64_update(ctx, (uint64_t)x);
}

BTC_UNUSED static size_t
btc_varint_size(uint64_t x) {
  if (x < 0xfd)
    return 1;

  if (x <= 0xffff)
    return 3;

  if (x <= 0xffffffff)
    return 5;

  return 9;
}

BTC_UNUSED static uint8_t *
btc_varint_write(uint8_t *zp, uint64_t x) {
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
btc_varint_read(uint64_t *zp, const uint8_t **xp, size_t *xn) {
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
btc_varint_update(struct sha256_s *ctx, uint64_t x) {
  uint8_t tmp[9];
  uint8_t *end = btc_varint_write(tmp, x);

  hash256_update(ctx, tmp, end - tmp);
}

BTC_UNUSED static size_t
btc_size_size(size_t x) {
  return btc_varint_size(x);
}

BTC_UNUSED static uint8_t *
btc_size_write(uint8_t *zp, size_t x) {
  return btc_varint_write(zp, x);
}

BTC_UNUSED static int
btc_size_read(size_t *zp, const uint8_t **xp, size_t *xn) {
  uint64_t z;

  if (!btc_varint_read(&z, xp, xn))
    return 0;

  if (z > 0xffffffff)
    return 0;

  *zp = z;

  return 1;
}

BTC_UNUSED static void
btc_size_update(struct sha256_s *ctx, size_t x) {
  return btc_varint_update(ctx, x);
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

BTC_UNUSED static void
btc_raw_update(struct sha256_s *ctx, const uint8_t *xp, size_t xn) {
  hash256_update(ctx, xp, xn);
}

#endif /* BTC_IMPL_INTERNAL_H */
