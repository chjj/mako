/*!
 * sha256.c - sha256 for mako
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/SHA-2
 *   https://tools.ietf.org/html/rfc4634
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
 * SHA256
 */

void
btc_sha256_init(btc_sha256_t *ctx) {
  ctx->state[0] = 0x6a09e667;
  ctx->state[1] = 0xbb67ae85;
  ctx->state[2] = 0x3c6ef372;
  ctx->state[3] = 0xa54ff53a;
  ctx->state[4] = 0x510e527f;
  ctx->state[5] = 0x9b05688c;
  ctx->state[6] = 0x1f83d9ab;
  ctx->state[7] = 0x5be0cd19;
  ctx->size = 0;
}

static void
sha256_transform(btc_sha256_t *ctx, const uint8_t *chunk) {
  uint32_t A = ctx->state[0];
  uint32_t B = ctx->state[1];
  uint32_t C = ctx->state[2];
  uint32_t D = ctx->state[3];
  uint32_t E = ctx->state[4];
  uint32_t F = ctx->state[5];
  uint32_t G = ctx->state[6];
  uint32_t H = ctx->state[7];
  uint32_t W[16];
  uint32_t w;

/* Note: the code in the RFC points out that Ch and Maj
 * can be optimized to use less bitwise ops.
 *
 * Original:
 *
 *   #define Ch(x, y, z) ((x & y) ^ (~x & z))
 *   #define Maj(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
 */
#define Ch(x, y, z) ((x & (y ^ z)) ^ z)
#define Maj(x, y, z) ((x & (y | z)) | (y & z))
#define Sigma0(x) (ROTR32(x,  2) ^ ROTR32(x, 13) ^ ROTR32(x, 22))
#define Sigma1(x) (ROTR32(x,  6) ^ ROTR32(x, 11) ^ ROTR32(x, 25))
#define sigma0(x) (ROTR32(x,  7) ^ ROTR32(x, 18) ^ (x >>  3))
#define sigma1(x) (ROTR32(x, 17) ^ ROTR32(x, 19) ^ (x >> 10))

/* Modulo by 16 to avoid allocating a large array. */
/* This trick is mentioned by the SHA1 RFC. */
#define WORD(i) (sigma1(W[(i -  2) & 15]) + W[(i -  7) & 15]  \
               + sigma0(W[(i - 15) & 15]) + W[(i - 16) & 15])

/* Loop body:
 *
 *   T1 = h + Sigma1(e) + Ch(e, f, g) + Kt + Wt
 *   T2 = Sigma0(a) + Maj(a, b, c)
 *   h = g
 *   g = f
 *   f = e
 *   e = d + T1
 *   d = c
 *   c = b
 *   b = a
 *   a = T1 + T2
 *
 * Reduces to:
 *
 *   T1 = h + Sigma1(e) + Ch(e, f, g) + Kt + Wt
 *   T2 = Sigma0(a) + Maj(a, b, c)
 *   d = d + T1
 *   h = T1 + T2
 *
 * Which further reduces to:
 *
 *   h = h + Sigma1(e) + Ch(e, f, g) + Kt + Wt
 *   d = d + h
 *   h = h + Sigma0(a) + Maj(a, b, c)
 */
#define R(a, b, c, d, e, f, g, h, i, k) do { \
  if (i < 16) /* Optimized out. */           \
    w = btc_read32be(chunk + i * 4);         \
  else                                       \
    w = WORD(i);                             \
                                             \
  W[i & 15] = w;                             \
                                             \
  h += Sigma1(e) + Ch(e, f, g) + k + w;      \
  d += h;                                    \
  h += Sigma0(a) + Maj(a, b, c);             \
} while (0)

  R(A, B, C, D, E, F, G, H,  0, 0x428a2f98);
  R(H, A, B, C, D, E, F, G,  1, 0x71374491);
  R(G, H, A, B, C, D, E, F,  2, 0xb5c0fbcf);
  R(F, G, H, A, B, C, D, E,  3, 0xe9b5dba5);
  R(E, F, G, H, A, B, C, D,  4, 0x3956c25b);
  R(D, E, F, G, H, A, B, C,  5, 0x59f111f1);
  R(C, D, E, F, G, H, A, B,  6, 0x923f82a4);
  R(B, C, D, E, F, G, H, A,  7, 0xab1c5ed5);
  R(A, B, C, D, E, F, G, H,  8, 0xd807aa98);
  R(H, A, B, C, D, E, F, G,  9, 0x12835b01);
  R(G, H, A, B, C, D, E, F, 10, 0x243185be);
  R(F, G, H, A, B, C, D, E, 11, 0x550c7dc3);
  R(E, F, G, H, A, B, C, D, 12, 0x72be5d74);
  R(D, E, F, G, H, A, B, C, 13, 0x80deb1fe);
  R(C, D, E, F, G, H, A, B, 14, 0x9bdc06a7);
  R(B, C, D, E, F, G, H, A, 15, 0xc19bf174);
  R(A, B, C, D, E, F, G, H, 16, 0xe49b69c1);
  R(H, A, B, C, D, E, F, G, 17, 0xefbe4786);
  R(G, H, A, B, C, D, E, F, 18, 0x0fc19dc6);
  R(F, G, H, A, B, C, D, E, 19, 0x240ca1cc);
  R(E, F, G, H, A, B, C, D, 20, 0x2de92c6f);
  R(D, E, F, G, H, A, B, C, 21, 0x4a7484aa);
  R(C, D, E, F, G, H, A, B, 22, 0x5cb0a9dc);
  R(B, C, D, E, F, G, H, A, 23, 0x76f988da);
  R(A, B, C, D, E, F, G, H, 24, 0x983e5152);
  R(H, A, B, C, D, E, F, G, 25, 0xa831c66d);
  R(G, H, A, B, C, D, E, F, 26, 0xb00327c8);
  R(F, G, H, A, B, C, D, E, 27, 0xbf597fc7);
  R(E, F, G, H, A, B, C, D, 28, 0xc6e00bf3);
  R(D, E, F, G, H, A, B, C, 29, 0xd5a79147);
  R(C, D, E, F, G, H, A, B, 30, 0x06ca6351);
  R(B, C, D, E, F, G, H, A, 31, 0x14292967);
  R(A, B, C, D, E, F, G, H, 32, 0x27b70a85);
  R(H, A, B, C, D, E, F, G, 33, 0x2e1b2138);
  R(G, H, A, B, C, D, E, F, 34, 0x4d2c6dfc);
  R(F, G, H, A, B, C, D, E, 35, 0x53380d13);
  R(E, F, G, H, A, B, C, D, 36, 0x650a7354);
  R(D, E, F, G, H, A, B, C, 37, 0x766a0abb);
  R(C, D, E, F, G, H, A, B, 38, 0x81c2c92e);
  R(B, C, D, E, F, G, H, A, 39, 0x92722c85);
  R(A, B, C, D, E, F, G, H, 40, 0xa2bfe8a1);
  R(H, A, B, C, D, E, F, G, 41, 0xa81a664b);
  R(G, H, A, B, C, D, E, F, 42, 0xc24b8b70);
  R(F, G, H, A, B, C, D, E, 43, 0xc76c51a3);
  R(E, F, G, H, A, B, C, D, 44, 0xd192e819);
  R(D, E, F, G, H, A, B, C, 45, 0xd6990624);
  R(C, D, E, F, G, H, A, B, 46, 0xf40e3585);
  R(B, C, D, E, F, G, H, A, 47, 0x106aa070);
  R(A, B, C, D, E, F, G, H, 48, 0x19a4c116);
  R(H, A, B, C, D, E, F, G, 49, 0x1e376c08);
  R(G, H, A, B, C, D, E, F, 50, 0x2748774c);
  R(F, G, H, A, B, C, D, E, 51, 0x34b0bcb5);
  R(E, F, G, H, A, B, C, D, 52, 0x391c0cb3);
  R(D, E, F, G, H, A, B, C, 53, 0x4ed8aa4a);
  R(C, D, E, F, G, H, A, B, 54, 0x5b9cca4f);
  R(B, C, D, E, F, G, H, A, 55, 0x682e6ff3);
  R(A, B, C, D, E, F, G, H, 56, 0x748f82ee);
  R(H, A, B, C, D, E, F, G, 57, 0x78a5636f);
  R(G, H, A, B, C, D, E, F, 58, 0x84c87814);
  R(F, G, H, A, B, C, D, E, 59, 0x8cc70208);
  R(E, F, G, H, A, B, C, D, 60, 0x90befffa);
  R(D, E, F, G, H, A, B, C, 61, 0xa4506ceb);
  R(C, D, E, F, G, H, A, B, 62, 0xbef9a3f7);
  R(B, C, D, E, F, G, H, A, 63, 0xc67178f2);

#undef Ch
#undef Maj
#undef Sigma0
#undef Sigma1
#undef sigma0
#undef sigma1
#undef WORD
#undef R

  ctx->state[0] += A;
  ctx->state[1] += B;
  ctx->state[2] += C;
  ctx->state[3] += D;
  ctx->state[4] += E;
  ctx->state[5] += F;
  ctx->state[6] += G;
  ctx->state[7] += H;
}

void
btc_sha256_update(btc_sha256_t *ctx, const void *data, size_t len) {
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

      sha256_transform(ctx, ctx->block);
    }

    while (len >= 64) {
      sha256_transform(ctx, raw);
      raw += 64;
      len -= 64;
    }
  }

  if (len > 0)
    memcpy(ctx->block + pos, raw, len);
}

void
btc_sha256_final(btc_sha256_t *ctx, uint8_t *out) {
  size_t pos = ctx->size & 63;
  int i;

  ctx->block[pos++] = 0x80;

  if (pos > 56) {
    while (pos < 64)
      ctx->block[pos++] = 0x00;

    sha256_transform(ctx, ctx->block);

    pos = 0;
  }

  while (pos < 56)
    ctx->block[pos++] = 0x00;

  btc_write64be(ctx->block + 56, ctx->size << 3);

  sha256_transform(ctx, ctx->block);

  for (i = 0; i < 8; i++)
    btc_write32be(out + i * 4, ctx->state[i]);
}

void
btc_sha256(uint8_t *out, const void *data, size_t size) {
  btc_sha256_t ctx;
  btc_sha256_init(&ctx);
  btc_sha256_update(&ctx, data, size);
  btc_sha256_final(&ctx, out);
}
