/*!
 * bio.h - binary parsing & serialization for mako
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifndef BTC_BIO_H
#define BTC_BIO_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "internal.h"

/*
 * Little Endian
 */

static BTC_INLINE uint16_t
btc_read16le(const uint8_t *xp) {
#if defined(BTC_BIGENDIAN)
  return ((uint16_t)xp[0] << 0)
       | ((uint16_t)xp[1] << 8);
#else
  uint16_t z;
  memcpy(&z, xp, sizeof(z));
  return z;
#endif
}

static BTC_INLINE void
btc_write16le(uint8_t *zp, uint16_t x) {
#if defined(BTC_BIGENDIAN)
  zp[0] = (x >> 0);
  zp[1] = (x >> 8);
#else
  memcpy(zp, &x, sizeof(x));
#endif
}

static BTC_INLINE uint32_t
btc_read32le(const uint8_t *xp) {
#if defined(BTC_BIGENDIAN)
  return ((uint32_t)xp[0] <<  0)
       | ((uint32_t)xp[1] <<  8)
       | ((uint32_t)xp[2] << 16)
       | ((uint32_t)xp[3] << 24);
#else
  uint32_t z;
  memcpy(&z, xp, sizeof(z));
  return z;
#endif
}

static BTC_INLINE void
btc_write32le(uint8_t *zp, uint32_t x) {
#if defined(BTC_BIGENDIAN)
  zp[0] = (x >>  0);
  zp[1] = (x >>  8);
  zp[2] = (x >> 16);
  zp[3] = (x >> 24);
#else
  memcpy(zp, &x, sizeof(x));
#endif
}

static BTC_INLINE uint64_t
btc_read64le(const uint8_t *xp) {
#if defined(BTC_BIGENDIAN)
  return ((uint64_t)xp[0] <<  0)
       | ((uint64_t)xp[1] <<  8)
       | ((uint64_t)xp[2] << 16)
       | ((uint64_t)xp[3] << 24)
       | ((uint64_t)xp[4] << 32)
       | ((uint64_t)xp[5] << 40)
       | ((uint64_t)xp[6] << 48)
       | ((uint64_t)xp[7] << 56);
#else
  uint64_t z;
  memcpy(&z, xp, sizeof(z));
  return z;
#endif
}

static BTC_INLINE void
btc_write64le(uint8_t *zp, uint64_t x) {
#if defined(BTC_BIGENDIAN)
  zp[0] = (x >>  0);
  zp[1] = (x >>  8);
  zp[2] = (x >> 16);
  zp[3] = (x >> 24);
  zp[4] = (x >> 32);
  zp[5] = (x >> 40);
  zp[6] = (x >> 48);
  zp[7] = (x >> 56);
#else
  memcpy(zp, &x, sizeof(x));
#endif
}

/*
 * Big Endian
 */

static BTC_INLINE uint16_t
btc_read16be(const uint8_t *xp) {
#if defined(BTC_BIGENDIAN)
  uint16_t z;
  memcpy(&z, xp, sizeof(z));
  return z;
#else
  return ((uint16_t)xp[0] << 8)
       | ((uint16_t)xp[1] << 0);
#endif
}

static BTC_INLINE void
btc_write16be(uint8_t *zp, uint16_t x) {
#if defined(BTC_BIGENDIAN)
  memcpy(zp, &x, sizeof(x));
#else
  zp[0] = (x >> 8);
  zp[1] = (x >> 0);
#endif
}

static BTC_INLINE uint32_t
btc_read32be(const uint8_t *xp) {
#if defined(BTC_BIGENDIAN)
  uint32_t z;
  memcpy(&z, xp, sizeof(z));
  return z;
#else
  return ((uint32_t)xp[0] << 24)
       | ((uint32_t)xp[1] << 16)
       | ((uint32_t)xp[2] <<  8)
       | ((uint32_t)xp[3] <<  0);
#endif
}

static BTC_INLINE void
btc_write32be(uint8_t *zp, uint32_t x) {
#if defined(BTC_BIGENDIAN)
  memcpy(zp, &x, sizeof(x));
#else
  zp[0] = (x >> 24);
  zp[1] = (x >> 16);
  zp[2] = (x >>  8);
  zp[3] = (x >>  0);
#endif
}

static BTC_INLINE uint64_t
btc_read64be(const uint8_t *xp) {
#if defined(BTC_BIGENDIAN)
  uint64_t z;
  memcpy(&z, xp, sizeof(z));
  return z;
#else
  return ((uint64_t)xp[0] << 56)
       | ((uint64_t)xp[1] << 48)
       | ((uint64_t)xp[2] << 40)
       | ((uint64_t)xp[3] << 32)
       | ((uint64_t)xp[4] << 24)
       | ((uint64_t)xp[5] << 16)
       | ((uint64_t)xp[6] <<  8)
       | ((uint64_t)xp[7] <<  0);
#endif
}

static BTC_INLINE void
btc_write64be(uint8_t *zp, uint64_t x) {
#if defined(BTC_BIGENDIAN)
  memcpy(zp, &x, sizeof(x));
#else
  zp[0] = (x >> 56);
  zp[1] = (x >> 48);
  zp[2] = (x >> 40);
  zp[3] = (x >> 32);
  zp[4] = (x >> 24);
  zp[5] = (x >> 16);
  zp[6] = (x >>  8);
  zp[7] = (x >>  0);
#endif
}

/*
 * Endianness Swapping
 *
 * Resources:
 *   https://gcc.gnu.org/onlinedocs/gcc/Other-Builtins.html
 *   https://stackoverflow.com/a/2637138
 */

#if BTC_GNUC_PREREQ(4, 8) || BTC_HAS_BUILTIN(__builtin_bswap16)
#  define btc_bswap16(x) __builtin_bswap16(x)
#else
static BTC_INLINE uint16_t
btc_bswap16(uint16_t x) {
  return (x << 8) | (x >> 8);
}
#endif

#if BTC_GNUC_PREREQ(4, 3) || BTC_HAS_BUILTIN(__builtin_bswap32)
#  define btc_bswap32(x) __builtin_bswap32(x)
#else
static BTC_INLINE uint32_t
btc_bswap32(uint32_t x) {
  x = ((x << 8) & UINT32_C(0xff00ff00))
    | ((x >> 8) & UINT32_C(0x00ff00ff));
  return (x >> 16) | (x << 16);
}
#endif

#if BTC_GNUC_PREREQ(4, 3) || BTC_HAS_BUILTIN(__builtin_bswap64)
#  define btc_bswap64(x) __builtin_bswap64(x)
#else
static BTC_INLINE uint64_t
btc_bswap64(uint64_t x) {
  x = ((x <<  8) & UINT64_C(0xff00ff00ff00ff00))
    | ((x >>  8) & UINT64_C(0x00ff00ff00ff00ff));
  x = ((x << 16) & UINT64_C(0xffff0000ffff0000))
    | ((x >> 16) & UINT64_C(0x0000ffff0000ffff));
  return (x << 32) | (x >> 32);
}
#endif

/*
 * Incrementation
 */

static BTC_INLINE void
btc_increment_le(uint8_t *x, size_t n) {
  unsigned int c = 1;
  size_t i;

  for (i = 0; i < n; i++) {
    c += (unsigned int)x[i];
    x[i] = c;
    c >>= 8;
  }
}

static BTC_INLINE void
btc_increment_le_var(uint8_t *x, size_t n) {
  uint8_t c = 1;
  size_t i;

  for (i = 0; i < n && c != 0; i++) {
    x[i] += c;
    c = (x[i] < c);
  }
}

static BTC_INLINE void
btc_increment_be(uint8_t *x, size_t n) {
  unsigned int c = 1;
  size_t i;

  for (i = n - 1; i != (size_t)-1; i--) {
    c += (unsigned int)x[i];
    x[i] = c;
    c >>= 8;
  }
}

static BTC_INLINE void
btc_increment_be_var(uint8_t *x, size_t n) {
  uint8_t c = 1;
  size_t i;

  for (i = n - 1; i != (size_t)-1 && c != 0; i--) {
    x[i] += c;
    c = (x[i] < c);
  }
}

/*
 * Rotates
 */

#define ROTL32(w, b) (((w) << (b)) | ((w) >> (32 - (b))))
#define ROTL64(w, b) (((w) << (b)) | ((w) >> (64 - (b))))
#define ROTR32(w, b) (((w) >> (b)) | ((w) << (32 - (b))))
#define ROTR64(w, b) (((w) >> (b)) | ((w) << (64 - (b))))

#endif /* BTC_BIO_H */
