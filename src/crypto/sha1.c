/*!
 * sha1.c - sha1 for mako
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/SHA-1
 *   https://tools.ietf.org/html/rfc3174
 *   http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf
 *
 * Unrolled loops generated with:
 *   https://gist.github.com/chjj/338a5ee212eefdff4431e4da65a2d4f7
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <mako/crypto/hash.h>
#include "../bio.h"

/*
 * SHA1
 */

void
btc_sha1_init(btc_sha1_t *ctx) {
  ctx->state[0] = 0x67452301;
  ctx->state[1] = 0xefcdab89;
  ctx->state[2] = 0x98badcfe;
  ctx->state[3] = 0x10325476;
  ctx->state[4] = 0xc3d2e1f0;
  ctx->size = 0;
}

static void
sha1_transform(btc_sha1_t *ctx, const uint8_t *chunk) {
  uint32_t A = ctx->state[0];
  uint32_t B = ctx->state[1];
  uint32_t C = ctx->state[2];
  uint32_t D = ctx->state[3];
  uint32_t E = ctx->state[4];
  uint32_t W[16];
  uint32_t w;

#define K1 0x5a827999
#define K2 0x6ed9eba1
#define K3 0x8f1bbcdc
#define K4 0xca62c1d6

/* Note: F1 is Ch, and F3 is Maj. We can utilize the
 * trick from the SHA-2 RFC C code to optimize them.
 *
 * Original:
 *
 *   #define F1(x, y, z) ((x & y) ^ (~x & z))
 *   #define F3(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
 */
#define F1(x, y, z) ((x & (y ^ z)) ^ z)
#define F2(x, y, z) (x ^ y ^ z)
#define F3(x, y, z) ((x & (y | z)) | (y & z))
#define F4(x, y, z) (x ^ y ^ z)

/* Modulo by 16 to avoid allocating a large array. */
/* This trick is mentioned in the above RFC. */
#define WORD(i) (W[(i -  3) & 15] ^ W[(i -  8) & 15] \
               ^ W[(i - 14) & 15] ^ W[(i - 16) & 15])

/* Loop body:
 *
 *   T = S^5(A) + F(B, C, D) + E + W(t) + K(t)
 *   E = D
 *   D = C
 *   C = S^30(B)
 *   B = A
 *   A = T
 *
 * Reduces to:
 *
 *   T = S^5(A) + F(B, C, D) + E + W(t) + K(t)
 *   E = T
 *   B = S^30(B)
 *
 * Which further reduces to:
 *
 *   E = E + S^5(A) + F(B, C, D) + W(t) + K(t)
 *   B = S^30(B)
 */
#define R(F, a, b, c, d, e, i, k) do {    \
  if (i < 16) { /* Optimized out. */      \
    w = btc_read32be(chunk + i * 4);      \
  } else {                                \
    w = WORD(i);                          \
    w = ROTL32(w, 1);                     \
  }                                       \
                                          \
  W[i & 15] = w;                          \
                                          \
  e += ROTL32(a, 5) + F(b, c, d) + w + k; \
  b = ROTL32(b, 30);                      \
} while (0)

  R(F1, A, B, C, D, E,  0, K1);
  R(F1, E, A, B, C, D,  1, K1);
  R(F1, D, E, A, B, C,  2, K1);
  R(F1, C, D, E, A, B,  3, K1);
  R(F1, B, C, D, E, A,  4, K1);
  R(F1, A, B, C, D, E,  5, K1);
  R(F1, E, A, B, C, D,  6, K1);
  R(F1, D, E, A, B, C,  7, K1);
  R(F1, C, D, E, A, B,  8, K1);
  R(F1, B, C, D, E, A,  9, K1);
  R(F1, A, B, C, D, E, 10, K1);
  R(F1, E, A, B, C, D, 11, K1);
  R(F1, D, E, A, B, C, 12, K1);
  R(F1, C, D, E, A, B, 13, K1);
  R(F1, B, C, D, E, A, 14, K1);
  R(F1, A, B, C, D, E, 15, K1);
  R(F1, E, A, B, C, D, 16, K1);
  R(F1, D, E, A, B, C, 17, K1);
  R(F1, C, D, E, A, B, 18, K1);
  R(F1, B, C, D, E, A, 19, K1);

  R(F2, A, B, C, D, E, 20, K2);
  R(F2, E, A, B, C, D, 21, K2);
  R(F2, D, E, A, B, C, 22, K2);
  R(F2, C, D, E, A, B, 23, K2);
  R(F2, B, C, D, E, A, 24, K2);
  R(F2, A, B, C, D, E, 25, K2);
  R(F2, E, A, B, C, D, 26, K2);
  R(F2, D, E, A, B, C, 27, K2);
  R(F2, C, D, E, A, B, 28, K2);
  R(F2, B, C, D, E, A, 29, K2);
  R(F2, A, B, C, D, E, 30, K2);
  R(F2, E, A, B, C, D, 31, K2);
  R(F2, D, E, A, B, C, 32, K2);
  R(F2, C, D, E, A, B, 33, K2);
  R(F2, B, C, D, E, A, 34, K2);
  R(F2, A, B, C, D, E, 35, K2);
  R(F2, E, A, B, C, D, 36, K2);
  R(F2, D, E, A, B, C, 37, K2);
  R(F2, C, D, E, A, B, 38, K2);
  R(F2, B, C, D, E, A, 39, K2);

  R(F3, A, B, C, D, E, 40, K3);
  R(F3, E, A, B, C, D, 41, K3);
  R(F3, D, E, A, B, C, 42, K3);
  R(F3, C, D, E, A, B, 43, K3);
  R(F3, B, C, D, E, A, 44, K3);
  R(F3, A, B, C, D, E, 45, K3);
  R(F3, E, A, B, C, D, 46, K3);
  R(F3, D, E, A, B, C, 47, K3);
  R(F3, C, D, E, A, B, 48, K3);
  R(F3, B, C, D, E, A, 49, K3);
  R(F3, A, B, C, D, E, 50, K3);
  R(F3, E, A, B, C, D, 51, K3);
  R(F3, D, E, A, B, C, 52, K3);
  R(F3, C, D, E, A, B, 53, K3);
  R(F3, B, C, D, E, A, 54, K3);
  R(F3, A, B, C, D, E, 55, K3);
  R(F3, E, A, B, C, D, 56, K3);
  R(F3, D, E, A, B, C, 57, K3);
  R(F3, C, D, E, A, B, 58, K3);
  R(F3, B, C, D, E, A, 59, K3);

  R(F4, A, B, C, D, E, 60, K4);
  R(F4, E, A, B, C, D, 61, K4);
  R(F4, D, E, A, B, C, 62, K4);
  R(F4, C, D, E, A, B, 63, K4);
  R(F4, B, C, D, E, A, 64, K4);
  R(F4, A, B, C, D, E, 65, K4);
  R(F4, E, A, B, C, D, 66, K4);
  R(F4, D, E, A, B, C, 67, K4);
  R(F4, C, D, E, A, B, 68, K4);
  R(F4, B, C, D, E, A, 69, K4);
  R(F4, A, B, C, D, E, 70, K4);
  R(F4, E, A, B, C, D, 71, K4);
  R(F4, D, E, A, B, C, 72, K4);
  R(F4, C, D, E, A, B, 73, K4);
  R(F4, B, C, D, E, A, 74, K4);
  R(F4, A, B, C, D, E, 75, K4);
  R(F4, E, A, B, C, D, 76, K4);
  R(F4, D, E, A, B, C, 77, K4);
  R(F4, C, D, E, A, B, 78, K4);
  R(F4, B, C, D, E, A, 79, K4);

#undef K1
#undef K2
#undef K3
#undef K4
#undef F1
#undef F2
#undef F3
#undef F4
#undef WORD
#undef R

  ctx->state[0] += A;
  ctx->state[1] += B;
  ctx->state[2] += C;
  ctx->state[3] += D;
  ctx->state[4] += E;
}

void
btc_sha1_update(btc_sha1_t *ctx, const void *data, size_t len) {
  const uint8_t *raw = (const uint8_t *)data;
  size_t pos = ctx->size & 63;
  size_t want = 64 - pos;

  ctx->size += len;

  if (len >= want) {
    if (pos > 0) {
      memcpy(ctx->block + pos, raw, want);

      raw += want;
      len -= want;
      pos = 0;

      sha1_transform(ctx, ctx->block);
    }

    while (len >= 64) {
      sha1_transform(ctx, raw);
      raw += 64;
      len -= 64;
    }
  }

  if (len > 0)
    memcpy(ctx->block + pos, raw, len);
}

void
btc_sha1_final(btc_sha1_t *ctx, uint8_t *out) {
  size_t pos = ctx->size & 63;
  int i;

  ctx->block[pos++] = 0x80;

  if (pos > 56) {
    while (pos < 64)
      ctx->block[pos++] = 0x00;

    sha1_transform(ctx, ctx->block);

    pos = 0;
  }

  while (pos < 56)
    ctx->block[pos++] = 0x00;

  btc_write64be(ctx->block + 56, ctx->size << 3);

  sha1_transform(ctx, ctx->block);

  for (i = 0; i < 5; i++)
    btc_write32be(out + i * 4, ctx->state[i]);
}

void
btc_sha1(uint8_t *out, const void *data, size_t size) {
  btc_sha1_t ctx;
  btc_sha1_init(&ctx);
  btc_sha1_update(&ctx, data, size);
  btc_sha1_final(&ctx, out);
}
