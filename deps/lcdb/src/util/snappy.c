/*!
 * snappy.c - snappy for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on golang/snappy:
 *   Copyright (c) 2011 The Snappy-Go Authors. All rights reserved.
 *   https://github.com/golang/snappy
 *
 * See LICENSE for more information.
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "coding.h"
#include "snappy.h"

/*
 * Constants
 */

#define MAX_TABLE_SIZE (1 << 11) /* Previously (1 << 14). */
#define INPUT_MARGIN (16 - 1)
#define MIN_BLOCK_SIZE (1 + 1 + INPUT_MARGIN)
#define MAX_BLOCK_SIZE 65536

enum {
  TAG_LITERAL = 0x00,
  TAG_COPY1   = 0x01,
  TAG_COPY2   = 0x02,
  TAG_COPY4   = 0x03
};

/*
 * Helpers
 */

#define load32 ldb_fixed32_decode
#define load64 ldb_fixed64_decode

static uint32_t
hash32(uint32_t x, int shift) {
  return (x * 0x1e35a7bd) >> shift;
}

/*
 * Encoding
 */

static uint8_t *
emit_literal(uint8_t *zp, const uint8_t *xp, size_t xn) {
  size_t n = xn - 1;

  if (n < 60) {
    *zp++ = (n << 2) | TAG_LITERAL;
  } else if (n < (1 << 8)) {
    *zp++ = (60 << 2) | TAG_LITERAL;
    *zp++ = n;
  } else {
    *zp++ = (61 << 2) | TAG_LITERAL;
    *zp++ = (n >> 0);
    *zp++ = (n >> 8);
  }

  memcpy(zp, xp, xn);

  zp += xn;

  return zp;
}

static uint8_t *
emit_copy(uint8_t *zp, uint32_t off, uint32_t len) {
  while (len >= 68) {
    *zp++ = (63 << 2) | TAG_COPY2;
    *zp++ = (off >> 0);
    *zp++ = (off >> 8);
    len -= 64;
  }

  if (len > 64) {
    *zp++ = (59 << 2) | TAG_COPY2;
    *zp++ = (off >> 0);
    *zp++ = (off >> 8);
    len -= 60;
  }

  if (len >= 12 || off >= 2048) {
    *zp++ = ((len - 1) << 2) | TAG_COPY2;
    *zp++ = (off >> 0);
    *zp++ = (off >> 8);
    return zp;
  }

  *zp++ = ((off >> 8) << 5) | ((len - 4) << 2) | TAG_COPY1;
  *zp++ = off;

  return zp;
}

static uint8_t *
encode_block(uint8_t *zp, const uint8_t *xp, size_t xn) {
  size_t limit = xn - INPUT_MARGIN;
  uint16_t table[MAX_TABLE_SIZE];
  size_t size = (1 << 8);
  int shift = 32 - 8;
  uint32_t next = 0;
  size_t emit = 0;
  size_t pos = 1;

  /* Outer loop. */
  size_t skip, npos, cand;

  /* Inner loop. */
  size_t chk, base;
  uint32_t prev, cur;
  uint64_t x;

  while (size < MAX_TABLE_SIZE && size < xn) {
    size *= 2;
    shift--;
  }

  assert(size <= MAX_TABLE_SIZE);

  memset(table, 0, size * sizeof(uint16_t));

  next = hash32(load32(xp + pos), shift);

  for (;;) {
    skip = 32;
    npos = pos;
    cand = 0;

    for (;;) {
      pos = npos;
      npos = pos + (skip >> 5);
      skip += (skip >> 5);

      if (npos > limit)
        goto finish;

      cand = table[next];

      table[next] = pos;

      next = hash32(load32(xp + npos), shift);

      if (load32(xp + pos) == load32(xp + cand))
        break;
    }

    zp = emit_literal(zp, xp + emit, pos - emit);

    for (;;) {
      base = pos;
      pos += 4;
      chk = cand + 4;

      while (pos < xn && xp[chk] == xp[pos])
        chk++, pos++;

      zp = emit_copy(zp, base - cand, pos - base);
      emit = pos;

      if (pos >= limit)
        goto finish;

      x = load64(xp + pos - 1);
      prev = hash32((x >> 0), shift);

      table[prev] = pos - 1;

      cur = hash32((x >> 8), shift);
      cand = table[cur];

      table[cur] = pos;

      if ((x >> 8) != load32(xp + cand)) {
        next = hash32((x >> 16), shift);
        pos++;
        break;
      }
    }
  }

finish:
  if (emit < xn)
    zp = emit_literal(zp, xp + emit, xn - emit);

  return zp;
}

/*
 * Decoding
 */

static int
decode_blocks(uint8_t *zp, size_t zn, const uint8_t *xp, size_t xn) {
  uint8_t *sp = zp;
  uint32_t off = 0;
  uint32_t len = 0;
  uint32_t i;

  while (xn > 0) {
    switch (xp[0] & 0x03) {
      case TAG_LITERAL: {
        uint32_t x = xp[0] >> 2;

        xp += 1;
        xn -= 1;

        if (x < 60) {
          ;
        } else if (x == 60) {
          if (xn < 1)
            return 0;

          x = xp[0];

          xp += 1;
          xn -= 1;
        } else if (x == 61) {
          if (xn < 2)
            return 0;

          x = ((uint32_t)xp[0] << 0)
            | ((uint32_t)xp[1] << 8);

          xp += 2;
          xn -= 2;
        } else if (x == 62) {
          if (xn < 3)
            return 0;

          x = ((uint32_t)xp[0] <<  0)
            | ((uint32_t)xp[1] <<  8)
            | ((uint32_t)xp[2] << 16);

          xp += 3;
          xn -= 3;
        } else if (x == 63) {
          if (xn < 4)
            return 0;

          x = ((uint32_t)xp[0] <<  0)
            | ((uint32_t)xp[1] <<  8)
            | ((uint32_t)xp[2] << 16)
            | ((uint32_t)xp[3] << 24);

          xp += 4;
          xn -= 4;
        }

        if (x >= 0x7fffffff)
          return 0;

        len = x + 1;

        if (len > zn || len > xn)
          return 0;

        memcpy(zp, xp, len);

        zp += len;
        zn -= len;
        xp += len;
        xn -= len;

        continue;
      }

      case TAG_COPY1: {
        if (xn < 2)
          return 0;

        len = 4 + ((xp[0] >> 2) & 0x7);
        off = ((uint32_t)(xp[0] & 0xe0) << 3) | xp[1];

        xp += 2;
        xn -= 2;

        break;
      }

      case TAG_COPY2: {
        if (xn < 3)
          return 0;

        len = 1 + (xp[0] >> 2);
        off = ((uint32_t)xp[1] << 0)
            | ((uint32_t)xp[2] << 8);

        xp += 3;
        xn -= 3;

        break;
      }

      case TAG_COPY4: {
        if (xn < 5)
          return 0;

        len = 1 + (xp[0] >> 2);
        off = ((uint32_t)xp[1] <<  0)
            | ((uint32_t)xp[2] <<  8)
            | ((uint32_t)xp[3] << 16)
            | ((uint32_t)xp[4] << 24);

        xp += 5;
        xn -= 5;

        break;
      }
    }

    if (off == 0 || off >= 0x80000000)
      return 0;

    if ((size_t)(zp - sp) < off || len > zn)
      return 0;

    if (off >= len) {
      memcpy(zp, zp - off, len);
    } else {
      for (i = 0; i < len; i++)
        zp[i] = (zp - off)[i];
    }

    zp += len;
    zn -= len;
  }

  if (zn != 0)
    return 0;

  return 1;
}

/*
 * Snappy
 */

int
snappy_encode_size(size_t *zn, size_t xn) {
  size_t n = xn;

  if (n > 0x7fffffff)
    return 0;

  n = 32 + n + (n / 6);

  if (n > 0x7fffffff)
    return 0;

  *zn = n;

  return 1;
}

size_t
snappy_encode(uint8_t *zp, const uint8_t *xp, size_t xn) {
  uint8_t *sp = zp;

  zp = ldb_varint32_write(zp, xn);

  while (xn >= MAX_BLOCK_SIZE) {
    zp = encode_block(zp, xp, MAX_BLOCK_SIZE);
    xp += MAX_BLOCK_SIZE;
    xn -= MAX_BLOCK_SIZE;
  }

  if (xn > 0) {
    if (xn >= MIN_BLOCK_SIZE)
      zp = encode_block(zp, xp, xn);
    else
      zp = emit_literal(zp, xp, xn);
  }

  return zp - sp;
}

int
snappy_decode_size(size_t *zn, const uint8_t *xp, size_t xn) {
  uint32_t n;

  if (!ldb_varint32_read(&n, &xp, &xn))
    return 0;

  if (n > 0x7fffffff)
    return 0;

  *zn = n;

  return 1;
}

int
snappy_decode(uint8_t *zp, const uint8_t *xp, size_t xn) {
  uint32_t zn;

  if (!ldb_varint32_read(&zn, &xp, &xn))
    return 0;

  if (zn > 0x7fffffff)
    return 0;

  return decode_blocks(zp, zn, xp, xn);
}
