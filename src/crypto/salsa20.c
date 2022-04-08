/*!
 * salsa20.c - salsa20 for mako
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 *
 * Resources
 *   https://en.wikipedia.org/wiki/Salsa20
 *   https://cr.yp.to/snuffle.html
 *   https://cr.yp.to/snuffle/spec.pdf
 *   https://cr.yp.to/snuffle/812.pdf
 *   http://www.ecrypt.eu.org/stream/salsa20pf.html
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <mako/crypto/stream.h>
#include <mako/util.h>

#include "../bio.h"
#include "../internal.h"

/*
 * Salsa20
 */

#define QROUND(x, a, b, c, d)      \
  x[b] ^= ROTL32(x[a] + x[d], 7);  \
  x[c] ^= ROTL32(x[b] + x[a], 9);  \
  x[d] ^= ROTL32(x[c] + x[b], 13); \
  x[a] ^= ROTL32(x[d] + x[c], 18)

void
btc_salsa20_init(btc_salsa20_t *ctx,
                 const uint8_t *key,
                 size_t key_len,
                 const uint8_t *nonce,
                 size_t nonce_len,
                 uint64_t counter) {
  uint8_t tmp[32];

  CHECK(key_len == 16 || key_len == 32);

  if (nonce_len >= 24) {
    btc_salsa20_derive(tmp, key, key_len, nonce);
    key = tmp;
    key_len = 32;
    nonce += 16;
    nonce_len -= 16;
  }

  ctx->state[0] = 0x61707865;
  ctx->state[1] = btc_read32le(key + 0);
  ctx->state[2] = btc_read32le(key + 4);
  ctx->state[3] = btc_read32le(key + 8);
  ctx->state[4] = btc_read32le(key + 12);
  ctx->state[5] = key_len < 32 ? 0x3120646e : 0x3320646e;

  if (nonce_len == 8) {
    ctx->state[6] = btc_read32le(nonce + 0);
    ctx->state[7] = btc_read32le(nonce + 4);
    ctx->state[8] = counter;
    ctx->state[9] = counter >> 32;
  } else if (nonce_len == 12) {
    ctx->state[6] = btc_read32le(nonce + 0);
    ctx->state[7] = btc_read32le(nonce + 4);
    ctx->state[8] = btc_read32le(nonce + 8);
    ctx->state[9] = counter;
  } else if (nonce_len == 16) {
    ctx->state[6] = btc_read32le(nonce + 0);
    ctx->state[7] = btc_read32le(nonce + 4);
    ctx->state[8] = btc_read32le(nonce + 8);
    ctx->state[9] = btc_read32le(nonce + 12);
  } else {
    btc_abort(); /* LCOV_EXCL_LINE */
  }

  ctx->state[10] = key_len < 32 ? 0x79622d36 : 0x79622d32;
  ctx->state[11] = btc_read32le(key + 16 % key_len);
  ctx->state[12] = btc_read32le(key + 20 % key_len);
  ctx->state[13] = btc_read32le(key + 24 % key_len);
  ctx->state[14] = btc_read32le(key + 28 % key_len);
  ctx->state[15] = 0x6b206574;

  ctx->pos = 0;

  btc_memzero(tmp, sizeof(tmp));
}

static void
salsa20_block(btc_salsa20_t *ctx, uint32_t *stream) {
  int i;

  for (i = 0; i < 16; i++)
    stream[i] = ctx->state[i];

  for (i = 0; i < 10; i++) {
    QROUND(stream,  0,  4,  8, 12);
    QROUND(stream,  5,  9, 13,  1);
    QROUND(stream, 10, 14,  2,  6);
    QROUND(stream, 15,  3,  7, 11);
    QROUND(stream,  0,  1,  2,  3);
    QROUND(stream,  5,  6,  7,  4);
    QROUND(stream, 10, 11,  8,  9);
    QROUND(stream, 15, 12, 13, 14);
  }

  for (i = 0; i < 16; i++)
    stream[i] += ctx->state[i];

#ifdef BTC_BIGENDIAN
    for (i = 0; i < 16; i++)
      stream[i] = btc_bswap32(stream[i]);
#endif

  ctx->state[8] += 1;
  ctx->state[9] += (ctx->state[8] < 1);
}

void
btc_salsa20_crypt(btc_salsa20_t *ctx,
                  uint8_t *dst,
                  const uint8_t *src,
                  size_t len) {
  uint8_t *bytes = (uint8_t *)ctx->stream;
  size_t pos = ctx->pos;
  size_t want = 64 - pos;

  if (len >= want) {
    if (pos > 0) {
      btc_memxor3(dst, src, bytes + pos, want);

      dst += want;
      src += want;
      len -= want;
      pos = 0;
    }

    while (len >= 64) {
      salsa20_block(ctx, ctx->stream);

      btc_memxor3(dst, src, bytes, 64);

      dst += 64;
      src += 64;
      len -= 64;
    }
  }

  if (len > 0) {
    if (pos == 0)
      salsa20_block(ctx, ctx->stream);

    btc_memxor3(dst, src, bytes + pos, len);

    pos += len;
  }

  ctx->pos = pos;
}

void
btc_salsa20_derive(uint8_t *out,
                   const uint8_t *key,
                   size_t key_len,
                   const uint8_t *nonce16) {
  uint32_t state[16];
  int i;

  CHECK(key_len == 16 || key_len == 32);

  state[0] = 0x61707865;
  state[1] = btc_read32le(key + 0);
  state[2] = btc_read32le(key + 4);
  state[3] = btc_read32le(key + 8);
  state[4] = btc_read32le(key + 12);
  state[5] = key_len < 32 ? 0x3120646e : 0x3320646e;
  state[6] = btc_read32le(nonce16 + 0);
  state[7] = btc_read32le(nonce16 + 4);
  state[8] = btc_read32le(nonce16 + 8);
  state[9] = btc_read32le(nonce16 + 12);
  state[10] = key_len < 32 ? 0x79622d36 : 0x79622d32;
  state[11] = btc_read32le(key + 16 % key_len);
  state[12] = btc_read32le(key + 20 % key_len);
  state[13] = btc_read32le(key + 24 % key_len);
  state[14] = btc_read32le(key + 28 % key_len);
  state[15] = 0x6b206574;

  for (i = 0; i < 10; i++) {
    QROUND(state,  0,  4,  8, 12);
    QROUND(state,  5,  9, 13,  1);
    QROUND(state, 10, 14,  2,  6);
    QROUND(state, 15,  3,  7, 11);
    QROUND(state,  0,  1,  2,  3);
    QROUND(state,  5,  6,  7,  4);
    QROUND(state, 10, 11,  8,  9);
    QROUND(state, 15, 12, 13, 14);
  }

  btc_write32le(out +  0, state[0]);
  btc_write32le(out +  4, state[5]);
  btc_write32le(out +  8, state[10]);
  btc_write32le(out + 12, state[15]);
  btc_write32le(out + 16, state[6]);
  btc_write32le(out + 20, state[7]);
  btc_write32le(out + 24, state[8]);
  btc_write32le(out + 28, state[9]);

  btc_memzero(state, sizeof(state));
}
