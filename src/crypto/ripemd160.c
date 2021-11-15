/*!
 * ripemd160.c - ripemd160 for mako
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/RIPEMD-160
 *   https://homes.esat.kuleuven.be/~bosselae/ripemd160/pdf/AB-9601/AB-9601.pdf
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
 * RIPEMD160
 */

void
btc_ripemd160_init(btc_ripemd160_t *ctx) {
  ctx->state[0] = 0x67452301;
  ctx->state[1] = 0xefcdab89;
  ctx->state[2] = 0x98badcfe;
  ctx->state[3] = 0x10325476;
  ctx->state[4] = 0xc3d2e1f0;
  ctx->size = 0;
}

static void
ripemd160_transform(btc_ripemd160_t *ctx, const uint8_t *chunk) {
  uint32_t AH, BH, CH, DH, EH;
  uint32_t A, B, C, D, E, T;
  uint32_t W[16];
  int i;

  for (i = 0; i < 16; i++)
    W[i] = btc_read32le(chunk + i * 4);

  A = ctx->state[0];
  B = ctx->state[1];
  C = ctx->state[2];
  D = ctx->state[3];
  E = ctx->state[4];

  AH = A;
  BH = B;
  CH = C;
  DH = D;
  EH = E;

#define K1 0x00000000
#define K2 0x5a827999
#define K3 0x6ed9eba1
#define K4 0x8f1bbcdc
#define K5 0xa953fd4e

#define KH1 0x50a28be6
#define KH2 0x5c4dd124
#define KH3 0x6d703ef3
#define KH4 0x7a6d76e9
#define KH5 0x00000000

#define F1(x, y, z) (x ^ y ^ z)
#define F2(x, y, z) ((x & y) | (~x & z))
#define F3(x, y, z) ((x | ~y) ^ z)
#define F4(x, y, z) ((x & z) | (y & ~z))
#define F5(x, y, z) (x ^ (y | ~z))

/* Operations in one step:
 *
 *   A = ((A + F(B, C, D) + X + K) <<< s) + E
 *   C = C <<< 10
 *
 * Loop body:
 *
 *   T = rol(A + F(j, B, C, D) + X[r(j)] + K(j), s[j]) + E
 *   A = E
 *   E = D
 *   D = rol(C, 10)
 *   C = B
 *   B = T
 */
#define R(F, a, b, c, d, e, i, k, s) do { \
  a += F(b, c, d) + W[i] + k;             \
  a = ROTL32(a, s) + e;                   \
  c = ROTL32(c, 10);                      \
} while (0)

  R(F1, A, B, C, D, E,  0, K1, 11);
  R(F1, E, A, B, C, D,  1, K1, 14);
  R(F1, D, E, A, B, C,  2, K1, 15);
  R(F1, C, D, E, A, B,  3, K1, 12);
  R(F1, B, C, D, E, A,  4, K1,  5);
  R(F1, A, B, C, D, E,  5, K1,  8);
  R(F1, E, A, B, C, D,  6, K1,  7);
  R(F1, D, E, A, B, C,  7, K1,  9);
  R(F1, C, D, E, A, B,  8, K1, 11);
  R(F1, B, C, D, E, A,  9, K1, 13);
  R(F1, A, B, C, D, E, 10, K1, 14);
  R(F1, E, A, B, C, D, 11, K1, 15);
  R(F1, D, E, A, B, C, 12, K1,  6);
  R(F1, C, D, E, A, B, 13, K1,  7);
  R(F1, B, C, D, E, A, 14, K1,  9);
  R(F1, A, B, C, D, E, 15, K1,  8);
  R(F2, E, A, B, C, D,  7, K2,  7);
  R(F2, D, E, A, B, C,  4, K2,  6);
  R(F2, C, D, E, A, B, 13, K2,  8);
  R(F2, B, C, D, E, A,  1, K2, 13);
  R(F2, A, B, C, D, E, 10, K2, 11);
  R(F2, E, A, B, C, D,  6, K2,  9);
  R(F2, D, E, A, B, C, 15, K2,  7);
  R(F2, C, D, E, A, B,  3, K2, 15);
  R(F2, B, C, D, E, A, 12, K2,  7);
  R(F2, A, B, C, D, E,  0, K2, 12);
  R(F2, E, A, B, C, D,  9, K2, 15);
  R(F2, D, E, A, B, C,  5, K2,  9);
  R(F2, C, D, E, A, B,  2, K2, 11);
  R(F2, B, C, D, E, A, 14, K2,  7);
  R(F2, A, B, C, D, E, 11, K2, 13);
  R(F2, E, A, B, C, D,  8, K2, 12);
  R(F3, D, E, A, B, C,  3, K3, 11);
  R(F3, C, D, E, A, B, 10, K3, 13);
  R(F3, B, C, D, E, A, 14, K3,  6);
  R(F3, A, B, C, D, E,  4, K3,  7);
  R(F3, E, A, B, C, D,  9, K3, 14);
  R(F3, D, E, A, B, C, 15, K3,  9);
  R(F3, C, D, E, A, B,  8, K3, 13);
  R(F3, B, C, D, E, A,  1, K3, 15);
  R(F3, A, B, C, D, E,  2, K3, 14);
  R(F3, E, A, B, C, D,  7, K3,  8);
  R(F3, D, E, A, B, C,  0, K3, 13);
  R(F3, C, D, E, A, B,  6, K3,  6);
  R(F3, B, C, D, E, A, 13, K3,  5);
  R(F3, A, B, C, D, E, 11, K3, 12);
  R(F3, E, A, B, C, D,  5, K3,  7);
  R(F3, D, E, A, B, C, 12, K3,  5);
  R(F4, C, D, E, A, B,  1, K4, 11);
  R(F4, B, C, D, E, A,  9, K4, 12);
  R(F4, A, B, C, D, E, 11, K4, 14);
  R(F4, E, A, B, C, D, 10, K4, 15);
  R(F4, D, E, A, B, C,  0, K4, 14);
  R(F4, C, D, E, A, B,  8, K4, 15);
  R(F4, B, C, D, E, A, 12, K4,  9);
  R(F4, A, B, C, D, E,  4, K4,  8);
  R(F4, E, A, B, C, D, 13, K4,  9);
  R(F4, D, E, A, B, C,  3, K4, 14);
  R(F4, C, D, E, A, B,  7, K4,  5);
  R(F4, B, C, D, E, A, 15, K4,  6);
  R(F4, A, B, C, D, E, 14, K4,  8);
  R(F4, E, A, B, C, D,  5, K4,  6);
  R(F4, D, E, A, B, C,  6, K4,  5);
  R(F4, C, D, E, A, B,  2, K4, 12);
  R(F5, B, C, D, E, A,  4, K5,  9);
  R(F5, A, B, C, D, E,  0, K5, 15);
  R(F5, E, A, B, C, D,  5, K5,  5);
  R(F5, D, E, A, B, C,  9, K5, 11);
  R(F5, C, D, E, A, B,  7, K5,  6);
  R(F5, B, C, D, E, A, 12, K5,  8);
  R(F5, A, B, C, D, E,  2, K5, 13);
  R(F5, E, A, B, C, D, 10, K5, 12);
  R(F5, D, E, A, B, C, 14, K5,  5);
  R(F5, C, D, E, A, B,  1, K5, 12);
  R(F5, B, C, D, E, A,  3, K5, 13);
  R(F5, A, B, C, D, E,  8, K5, 14);
  R(F5, E, A, B, C, D, 11, K5, 11);
  R(F5, D, E, A, B, C,  6, K5,  8);
  R(F5, C, D, E, A, B, 15, K5,  5);
  R(F5, B, C, D, E, A, 13, K5,  6);

  R(F5, AH, BH, CH, DH, EH,  5, KH1,  8);
  R(F5, EH, AH, BH, CH, DH, 14, KH1,  9);
  R(F5, DH, EH, AH, BH, CH,  7, KH1,  9);
  R(F5, CH, DH, EH, AH, BH,  0, KH1, 11);
  R(F5, BH, CH, DH, EH, AH,  9, KH1, 13);
  R(F5, AH, BH, CH, DH, EH,  2, KH1, 15);
  R(F5, EH, AH, BH, CH, DH, 11, KH1, 15);
  R(F5, DH, EH, AH, BH, CH,  4, KH1,  5);
  R(F5, CH, DH, EH, AH, BH, 13, KH1,  7);
  R(F5, BH, CH, DH, EH, AH,  6, KH1,  7);
  R(F5, AH, BH, CH, DH, EH, 15, KH1,  8);
  R(F5, EH, AH, BH, CH, DH,  8, KH1, 11);
  R(F5, DH, EH, AH, BH, CH,  1, KH1, 14);
  R(F5, CH, DH, EH, AH, BH, 10, KH1, 14);
  R(F5, BH, CH, DH, EH, AH,  3, KH1, 12);
  R(F5, AH, BH, CH, DH, EH, 12, KH1,  6);
  R(F4, EH, AH, BH, CH, DH,  6, KH2,  9);
  R(F4, DH, EH, AH, BH, CH, 11, KH2, 13);
  R(F4, CH, DH, EH, AH, BH,  3, KH2, 15);
  R(F4, BH, CH, DH, EH, AH,  7, KH2,  7);
  R(F4, AH, BH, CH, DH, EH,  0, KH2, 12);
  R(F4, EH, AH, BH, CH, DH, 13, KH2,  8);
  R(F4, DH, EH, AH, BH, CH,  5, KH2,  9);
  R(F4, CH, DH, EH, AH, BH, 10, KH2, 11);
  R(F4, BH, CH, DH, EH, AH, 14, KH2,  7);
  R(F4, AH, BH, CH, DH, EH, 15, KH2,  7);
  R(F4, EH, AH, BH, CH, DH,  8, KH2, 12);
  R(F4, DH, EH, AH, BH, CH, 12, KH2,  7);
  R(F4, CH, DH, EH, AH, BH,  4, KH2,  6);
  R(F4, BH, CH, DH, EH, AH,  9, KH2, 15);
  R(F4, AH, BH, CH, DH, EH,  1, KH2, 13);
  R(F4, EH, AH, BH, CH, DH,  2, KH2, 11);
  R(F3, DH, EH, AH, BH, CH, 15, KH3,  9);
  R(F3, CH, DH, EH, AH, BH,  5, KH3,  7);
  R(F3, BH, CH, DH, EH, AH,  1, KH3, 15);
  R(F3, AH, BH, CH, DH, EH,  3, KH3, 11);
  R(F3, EH, AH, BH, CH, DH,  7, KH3,  8);
  R(F3, DH, EH, AH, BH, CH, 14, KH3,  6);
  R(F3, CH, DH, EH, AH, BH,  6, KH3,  6);
  R(F3, BH, CH, DH, EH, AH,  9, KH3, 14);
  R(F3, AH, BH, CH, DH, EH, 11, KH3, 12);
  R(F3, EH, AH, BH, CH, DH,  8, KH3, 13);
  R(F3, DH, EH, AH, BH, CH, 12, KH3,  5);
  R(F3, CH, DH, EH, AH, BH,  2, KH3, 14);
  R(F3, BH, CH, DH, EH, AH, 10, KH3, 13);
  R(F3, AH, BH, CH, DH, EH,  0, KH3, 13);
  R(F3, EH, AH, BH, CH, DH,  4, KH3,  7);
  R(F3, DH, EH, AH, BH, CH, 13, KH3,  5);
  R(F2, CH, DH, EH, AH, BH,  8, KH4, 15);
  R(F2, BH, CH, DH, EH, AH,  6, KH4,  5);
  R(F2, AH, BH, CH, DH, EH,  4, KH4,  8);
  R(F2, EH, AH, BH, CH, DH,  1, KH4, 11);
  R(F2, DH, EH, AH, BH, CH,  3, KH4, 14);
  R(F2, CH, DH, EH, AH, BH, 11, KH4, 14);
  R(F2, BH, CH, DH, EH, AH, 15, KH4,  6);
  R(F2, AH, BH, CH, DH, EH,  0, KH4, 14);
  R(F2, EH, AH, BH, CH, DH,  5, KH4,  6);
  R(F2, DH, EH, AH, BH, CH, 12, KH4,  9);
  R(F2, CH, DH, EH, AH, BH,  2, KH4, 12);
  R(F2, BH, CH, DH, EH, AH, 13, KH4,  9);
  R(F2, AH, BH, CH, DH, EH,  9, KH4, 12);
  R(F2, EH, AH, BH, CH, DH,  7, KH4,  5);
  R(F2, DH, EH, AH, BH, CH, 10, KH4, 15);
  R(F2, CH, DH, EH, AH, BH, 14, KH4,  8);
  R(F1, BH, CH, DH, EH, AH, 12, KH5,  8);
  R(F1, AH, BH, CH, DH, EH, 15, KH5,  5);
  R(F1, EH, AH, BH, CH, DH, 10, KH5, 12);
  R(F1, DH, EH, AH, BH, CH,  4, KH5,  9);
  R(F1, CH, DH, EH, AH, BH,  1, KH5, 12);
  R(F1, BH, CH, DH, EH, AH,  5, KH5,  5);
  R(F1, AH, BH, CH, DH, EH,  8, KH5, 14);
  R(F1, EH, AH, BH, CH, DH,  7, KH5,  6);
  R(F1, DH, EH, AH, BH, CH,  6, KH5,  8);
  R(F1, CH, DH, EH, AH, BH,  2, KH5, 13);
  R(F1, BH, CH, DH, EH, AH, 13, KH5,  6);
  R(F1, AH, BH, CH, DH, EH, 14, KH5,  5);
  R(F1, EH, AH, BH, CH, DH,  0, KH5, 15);
  R(F1, DH, EH, AH, BH, CH,  3, KH5, 13);
  R(F1, CH, DH, EH, AH, BH,  9, KH5, 11);
  R(F1, BH, CH, DH, EH, AH, 11, KH5, 11);

#undef K1
#undef K2
#undef K3
#undef K4
#undef K5
#undef KH1
#undef KH2
#undef KH3
#undef KH4
#undef KH5
#undef F1
#undef F2
#undef F3
#undef F4
#undef F5
#undef R

  T = ctx->state[1] + C + DH;

  ctx->state[1] = ctx->state[2] + D + EH;
  ctx->state[2] = ctx->state[3] + E + AH;
  ctx->state[3] = ctx->state[4] + A + BH;
  ctx->state[4] = ctx->state[0] + B + CH;
  ctx->state[0] = T;
}

void
btc_ripemd160_update(btc_ripemd160_t *ctx, const void *data, size_t len) {
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

      ripemd160_transform(ctx, ctx->block);
    }

    while (len >= 64) {
      ripemd160_transform(ctx, raw);
      raw += 64;
      len -= 64;
    }
  }

  if (len > 0)
    memcpy(ctx->block + pos, raw, len);
}

void
btc_ripemd160_final(btc_ripemd160_t *ctx, uint8_t *out) {
  size_t pos = ctx->size & 63;
  int i;

  ctx->block[pos++] = 0x80;

  if (pos > 56) {
    while (pos < 64)
      ctx->block[pos++] = 0x00;

    ripemd160_transform(ctx, ctx->block);

    pos = 0;
  }

  while (pos < 56)
    ctx->block[pos++] = 0x00;

  btc_write64le(ctx->block + 56, ctx->size << 3);

  ripemd160_transform(ctx, ctx->block);

  for (i = 0; i < 5; i++)
    btc_write32le(out + i * 4, ctx->state[i]);
}

void
btc_ripemd160(uint8_t *out, const void *data, size_t size) {
  btc_ripemd160_t ctx;
  btc_ripemd160_init(&ctx);
  btc_ripemd160_update(&ctx, data, size);
  btc_ripemd160_final(&ctx, out);
}
