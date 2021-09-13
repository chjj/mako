/*!
 * bio.h - binary parsing & serialization for libsatoshi
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef BTC_BIO_H
#define BTC_BIO_H

#include <stddef.h>
#include <stdint.h>
#include "internal.h"

/*
 * Little Endian
 */

static BTC_INLINE uint16_t
read16le(const uint8_t *src) {
  return ((uint16_t)src[1] << 8)
       | ((uint16_t)src[0] << 0);
}

static BTC_INLINE void
write16le(uint8_t *dst, uint16_t w) {
  dst[1] = w >> 8;
  dst[0] = w >> 0;
}

static BTC_INLINE uint32_t
read32le(const uint8_t *src) {
  return ((uint32_t)src[3] << 24)
       | ((uint32_t)src[2] << 16)
       | ((uint32_t)src[1] <<  8)
       | ((uint32_t)src[0] <<  0);
}

static BTC_INLINE void
write32le(uint8_t *dst, uint32_t w) {
  dst[3] = w >> 24;
  dst[2] = w >> 16;
  dst[1] = w >>  8;
  dst[0] = w >>  0;
}

static BTC_INLINE uint64_t
read64le(const uint8_t *src) {
  return ((uint64_t)src[7] << 56)
       | ((uint64_t)src[6] << 48)
       | ((uint64_t)src[5] << 40)
       | ((uint64_t)src[4] << 32)
       | ((uint64_t)src[3] << 24)
       | ((uint64_t)src[2] << 16)
       | ((uint64_t)src[1] <<  8)
       | ((uint64_t)src[0] <<  0);
}

static BTC_INLINE void
write64le(uint8_t *dst, uint64_t w) {
  dst[7] = w >> 56;
  dst[6] = w >> 48;
  dst[5] = w >> 40;
  dst[4] = w >> 32;
  dst[3] = w >> 24;
  dst[2] = w >> 16;
  dst[1] = w >>  8;
  dst[0] = w >>  0;
}

/*
 * Big Endian
 */

static BTC_INLINE uint16_t
read16be(const uint8_t *src) {
  return ((uint16_t)src[0] << 8)
       | ((uint16_t)src[1] << 0);
}

static BTC_INLINE void
write16be(uint8_t *dst, uint16_t w) {
  dst[0] = w >> 8;
  dst[1] = w >> 0;
}

static BTC_INLINE uint32_t
read32be(const uint8_t *src) {
  return ((uint32_t)src[0] << 24)
       | ((uint32_t)src[1] << 16)
       | ((uint32_t)src[2] <<  8)
       | ((uint32_t)src[3] <<  0);
}

static BTC_INLINE void
write32be(uint8_t *dst, uint32_t w) {
  dst[0] = w >> 24;
  dst[1] = w >> 16;
  dst[2] = w >>  8;
  dst[3] = w >>  0;
}

static BTC_INLINE uint64_t
read64be(const uint8_t *src) {
  return ((uint64_t)src[0] << 56)
       | ((uint64_t)src[1] << 48)
       | ((uint64_t)src[2] << 40)
       | ((uint64_t)src[3] << 32)
       | ((uint64_t)src[4] << 24)
       | ((uint64_t)src[5] << 16)
       | ((uint64_t)src[6] <<  8)
       | ((uint64_t)src[7] <<  0);
}

static BTC_INLINE void
write64be(uint8_t *dst, uint64_t w) {
  dst[0] = w >> 56;
  dst[1] = w >> 48;
  dst[2] = w >> 40;
  dst[3] = w >> 32;
  dst[4] = w >> 24;
  dst[5] = w >> 16;
  dst[6] = w >>  8;
  dst[7] = w >>  0;
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
increment_le(uint8_t *x, size_t n) {
  unsigned int c = 1;
  size_t i;

  for (i = 0; i < n; i++) {
    c += (unsigned int)x[i];
    x[i] = c;
    c >>= 8;
  }
}

static BTC_INLINE void
increment_le_var(uint8_t *x, size_t n) {
  uint8_t c = 1;
  size_t i;

  for (i = 0; i < n && c != 0; i++) {
    x[i] += c;
    c = (x[i] < c);
  }
}

static BTC_INLINE void
increment_be(uint8_t *x, size_t n) {
  unsigned int c = 1;
  size_t i;

  for (i = n - 1; i != (size_t)-1; i--) {
    c += (unsigned int)x[i];
    x[i] = c;
    c >>= 8;
  }
}

static BTC_INLINE void
increment_be_var(uint8_t *x, size_t n) {
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
