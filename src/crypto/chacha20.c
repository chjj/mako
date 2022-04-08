/*!
 * chacha20.c - chacha20 for mako
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/Chacha20
 *   https://tools.ietf.org/html/rfc7539#section-2
 *   https://cr.yp.to/chacha.html
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <mako/crypto/stream.h>
#include <mako/util.h>

#include "../bio.h"
#include "../internal.h"

/*
 * ChaCha20
 */

#define QROUND(x, a, b, c, d)                   \
  x[a] += x[b]; x[d] = ROTL32(x[d] ^ x[a], 16); \
  x[c] += x[d]; x[b] = ROTL32(x[b] ^ x[c], 12); \
  x[a] += x[b]; x[d] = ROTL32(x[d] ^ x[a], 8);  \
  x[c] += x[d]; x[b] = ROTL32(x[b] ^ x[c], 7)

void
btc_chacha20_init(btc_chacha20_t *ctx,
                  const uint8_t *key,
                  size_t key_len,
                  const uint8_t *nonce,
                  size_t nonce_len,
                  uint64_t counter) {
  uint8_t tmp[32];

  CHECK(key_len == 16 || key_len == 32);

  ctx->state[0] = 0x61707865;
  ctx->state[1] = key_len < 32 ? 0x3120646e : 0x3320646e;
  ctx->state[2] = key_len < 32 ? 0x79622d36 : 0x79622d32;
  ctx->state[3] = 0x6b206574;
  ctx->state[4] = btc_read32le(key + 0);
  ctx->state[5] = btc_read32le(key + 4);
  ctx->state[6] = btc_read32le(key + 8);
  ctx->state[7] = btc_read32le(key + 12);
  ctx->state[8] = btc_read32le(key + 16 % key_len);
  ctx->state[9] = btc_read32le(key + 20 % key_len);
  ctx->state[10] = btc_read32le(key + 24 % key_len);
  ctx->state[11] = btc_read32le(key + 28 % key_len);
  ctx->state[12] = counter;

  if (nonce_len == 8) {
    ctx->state[13] = counter >> 32;
    ctx->state[14] = btc_read32le(nonce + 0);
    ctx->state[15] = btc_read32le(nonce + 4);
  } else if (nonce_len == 12) {
    ctx->state[13] = btc_read32le(nonce + 0);
    ctx->state[14] = btc_read32le(nonce + 4);
    ctx->state[15] = btc_read32le(nonce + 8);
  } else if (nonce_len == 16) {
    ctx->state[12] = btc_read32le(nonce + 0);
    ctx->state[13] = btc_read32le(nonce + 4);
    ctx->state[14] = btc_read32le(nonce + 8);
    ctx->state[15] = btc_read32le(nonce + 12);
  } else {
    btc_abort(); /* LCOV_EXCL_LINE */
  }

  ctx->pos = 0;

  btc_memzero(tmp, sizeof(tmp));
}

static void
chacha20_block(btc_chacha20_t *ctx, uint32_t *stream) {
  int i;

  for (i = 0; i < 16; i++)
    stream[i] = ctx->state[i];

  for (i = 0; i < 10; i++) {
    QROUND(stream, 0, 4,  8, 12);
    QROUND(stream, 1, 5,  9, 13);
    QROUND(stream, 2, 6, 10, 14);
    QROUND(stream, 3, 7, 11, 15);
    QROUND(stream, 0, 5, 10, 15);
    QROUND(stream, 1, 6, 11, 12);
    QROUND(stream, 2, 7,  8, 13);
    QROUND(stream, 3, 4,  9, 14);
  }

  for (i = 0; i < 16; i++)
    stream[i] += ctx->state[i];

#ifdef BTC_BIGENDIAN
  for (i = 0; i < 16; i++)
    stream[i] = btc_bswap32(stream[i]);
#endif

  ctx->state[12] += 1;
  ctx->state[13] += (ctx->state[12] < 1);
}

void
btc_chacha20_crypt(btc_chacha20_t *ctx,
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
      chacha20_block(ctx, ctx->stream);

      btc_memxor3(dst, src, bytes, 64);

      dst += 64;
      src += 64;
      len -= 64;
    }
  }

  if (len > 0) {
    if (pos == 0)
      chacha20_block(ctx, ctx->stream);

    btc_memxor3(dst, src, bytes + pos, len);

    pos += len;
  }

  ctx->pos = pos;
}
