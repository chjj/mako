/*!
 * sha512.c - sha512 for mako
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
 * SHA512
 */

void
btc_sha512_init(btc_sha512_t *ctx) {
  ctx->state[0] = UINT64_C(0x6a09e667f3bcc908);
  ctx->state[1] = UINT64_C(0xbb67ae8584caa73b);
  ctx->state[2] = UINT64_C(0x3c6ef372fe94f82b);
  ctx->state[3] = UINT64_C(0xa54ff53a5f1d36f1);
  ctx->state[4] = UINT64_C(0x510e527fade682d1);
  ctx->state[5] = UINT64_C(0x9b05688c2b3e6c1f);
  ctx->state[6] = UINT64_C(0x1f83d9abfb41bd6b);
  ctx->state[7] = UINT64_C(0x5be0cd19137e2179);

  ctx->size[0] = 0;
  ctx->size[1] = 0;
}

static void
sha512_transform(btc_sha512_t *ctx, const uint8_t *chunk) {
  uint64_t A = ctx->state[0];
  uint64_t B = ctx->state[1];
  uint64_t C = ctx->state[2];
  uint64_t D = ctx->state[3];
  uint64_t E = ctx->state[4];
  uint64_t F = ctx->state[5];
  uint64_t G = ctx->state[6];
  uint64_t H = ctx->state[7];
  uint64_t W[16];
  uint64_t w;

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
#define Sigma0(x) (ROTR64(x, 28) ^ ROTR64(x, 34) ^ ROTR64(x, 39))
#define Sigma1(x) (ROTR64(x, 14) ^ ROTR64(x, 18) ^ ROTR64(x, 41))
#define sigma0(x) (ROTR64(x,  1) ^ ROTR64(x,  8) ^ (x >> 7))
#define sigma1(x) (ROTR64(x, 19) ^ ROTR64(x, 61) ^ (x >> 6))

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
    w = btc_read64be(chunk + i * 8);         \
  else                                       \
    w = WORD(i);                             \
                                             \
  W[i & 15] = w;                             \
                                             \
  h += Sigma1(e) + Ch(e, f, g) + k + w;      \
  d += h;                                    \
  h += Sigma0(a) + Maj(a, b, c);             \
} while (0)

  R(A, B, C, D, E, F, G, H,  0, UINT64_C(0x428a2f98d728ae22));
  R(H, A, B, C, D, E, F, G,  1, UINT64_C(0x7137449123ef65cd));
  R(G, H, A, B, C, D, E, F,  2, UINT64_C(0xb5c0fbcfec4d3b2f));
  R(F, G, H, A, B, C, D, E,  3, UINT64_C(0xe9b5dba58189dbbc));
  R(E, F, G, H, A, B, C, D,  4, UINT64_C(0x3956c25bf348b538));
  R(D, E, F, G, H, A, B, C,  5, UINT64_C(0x59f111f1b605d019));
  R(C, D, E, F, G, H, A, B,  6, UINT64_C(0x923f82a4af194f9b));
  R(B, C, D, E, F, G, H, A,  7, UINT64_C(0xab1c5ed5da6d8118));
  R(A, B, C, D, E, F, G, H,  8, UINT64_C(0xd807aa98a3030242));
  R(H, A, B, C, D, E, F, G,  9, UINT64_C(0x12835b0145706fbe));
  R(G, H, A, B, C, D, E, F, 10, UINT64_C(0x243185be4ee4b28c));
  R(F, G, H, A, B, C, D, E, 11, UINT64_C(0x550c7dc3d5ffb4e2));
  R(E, F, G, H, A, B, C, D, 12, UINT64_C(0x72be5d74f27b896f));
  R(D, E, F, G, H, A, B, C, 13, UINT64_C(0x80deb1fe3b1696b1));
  R(C, D, E, F, G, H, A, B, 14, UINT64_C(0x9bdc06a725c71235));
  R(B, C, D, E, F, G, H, A, 15, UINT64_C(0xc19bf174cf692694));
  R(A, B, C, D, E, F, G, H, 16, UINT64_C(0xe49b69c19ef14ad2));
  R(H, A, B, C, D, E, F, G, 17, UINT64_C(0xefbe4786384f25e3));
  R(G, H, A, B, C, D, E, F, 18, UINT64_C(0x0fc19dc68b8cd5b5));
  R(F, G, H, A, B, C, D, E, 19, UINT64_C(0x240ca1cc77ac9c65));
  R(E, F, G, H, A, B, C, D, 20, UINT64_C(0x2de92c6f592b0275));
  R(D, E, F, G, H, A, B, C, 21, UINT64_C(0x4a7484aa6ea6e483));
  R(C, D, E, F, G, H, A, B, 22, UINT64_C(0x5cb0a9dcbd41fbd4));
  R(B, C, D, E, F, G, H, A, 23, UINT64_C(0x76f988da831153b5));
  R(A, B, C, D, E, F, G, H, 24, UINT64_C(0x983e5152ee66dfab));
  R(H, A, B, C, D, E, F, G, 25, UINT64_C(0xa831c66d2db43210));
  R(G, H, A, B, C, D, E, F, 26, UINT64_C(0xb00327c898fb213f));
  R(F, G, H, A, B, C, D, E, 27, UINT64_C(0xbf597fc7beef0ee4));
  R(E, F, G, H, A, B, C, D, 28, UINT64_C(0xc6e00bf33da88fc2));
  R(D, E, F, G, H, A, B, C, 29, UINT64_C(0xd5a79147930aa725));
  R(C, D, E, F, G, H, A, B, 30, UINT64_C(0x06ca6351e003826f));
  R(B, C, D, E, F, G, H, A, 31, UINT64_C(0x142929670a0e6e70));
  R(A, B, C, D, E, F, G, H, 32, UINT64_C(0x27b70a8546d22ffc));
  R(H, A, B, C, D, E, F, G, 33, UINT64_C(0x2e1b21385c26c926));
  R(G, H, A, B, C, D, E, F, 34, UINT64_C(0x4d2c6dfc5ac42aed));
  R(F, G, H, A, B, C, D, E, 35, UINT64_C(0x53380d139d95b3df));
  R(E, F, G, H, A, B, C, D, 36, UINT64_C(0x650a73548baf63de));
  R(D, E, F, G, H, A, B, C, 37, UINT64_C(0x766a0abb3c77b2a8));
  R(C, D, E, F, G, H, A, B, 38, UINT64_C(0x81c2c92e47edaee6));
  R(B, C, D, E, F, G, H, A, 39, UINT64_C(0x92722c851482353b));
  R(A, B, C, D, E, F, G, H, 40, UINT64_C(0xa2bfe8a14cf10364));
  R(H, A, B, C, D, E, F, G, 41, UINT64_C(0xa81a664bbc423001));
  R(G, H, A, B, C, D, E, F, 42, UINT64_C(0xc24b8b70d0f89791));
  R(F, G, H, A, B, C, D, E, 43, UINT64_C(0xc76c51a30654be30));
  R(E, F, G, H, A, B, C, D, 44, UINT64_C(0xd192e819d6ef5218));
  R(D, E, F, G, H, A, B, C, 45, UINT64_C(0xd69906245565a910));
  R(C, D, E, F, G, H, A, B, 46, UINT64_C(0xf40e35855771202a));
  R(B, C, D, E, F, G, H, A, 47, UINT64_C(0x106aa07032bbd1b8));
  R(A, B, C, D, E, F, G, H, 48, UINT64_C(0x19a4c116b8d2d0c8));
  R(H, A, B, C, D, E, F, G, 49, UINT64_C(0x1e376c085141ab53));
  R(G, H, A, B, C, D, E, F, 50, UINT64_C(0x2748774cdf8eeb99));
  R(F, G, H, A, B, C, D, E, 51, UINT64_C(0x34b0bcb5e19b48a8));
  R(E, F, G, H, A, B, C, D, 52, UINT64_C(0x391c0cb3c5c95a63));
  R(D, E, F, G, H, A, B, C, 53, UINT64_C(0x4ed8aa4ae3418acb));
  R(C, D, E, F, G, H, A, B, 54, UINT64_C(0x5b9cca4f7763e373));
  R(B, C, D, E, F, G, H, A, 55, UINT64_C(0x682e6ff3d6b2b8a3));
  R(A, B, C, D, E, F, G, H, 56, UINT64_C(0x748f82ee5defb2fc));
  R(H, A, B, C, D, E, F, G, 57, UINT64_C(0x78a5636f43172f60));
  R(G, H, A, B, C, D, E, F, 58, UINT64_C(0x84c87814a1f0ab72));
  R(F, G, H, A, B, C, D, E, 59, UINT64_C(0x8cc702081a6439ec));
  R(E, F, G, H, A, B, C, D, 60, UINT64_C(0x90befffa23631e28));
  R(D, E, F, G, H, A, B, C, 61, UINT64_C(0xa4506cebde82bde9));
  R(C, D, E, F, G, H, A, B, 62, UINT64_C(0xbef9a3f7b2c67915));
  R(B, C, D, E, F, G, H, A, 63, UINT64_C(0xc67178f2e372532b));
  R(A, B, C, D, E, F, G, H, 64, UINT64_C(0xca273eceea26619c));
  R(H, A, B, C, D, E, F, G, 65, UINT64_C(0xd186b8c721c0c207));
  R(G, H, A, B, C, D, E, F, 66, UINT64_C(0xeada7dd6cde0eb1e));
  R(F, G, H, A, B, C, D, E, 67, UINT64_C(0xf57d4f7fee6ed178));
  R(E, F, G, H, A, B, C, D, 68, UINT64_C(0x06f067aa72176fba));
  R(D, E, F, G, H, A, B, C, 69, UINT64_C(0x0a637dc5a2c898a6));
  R(C, D, E, F, G, H, A, B, 70, UINT64_C(0x113f9804bef90dae));
  R(B, C, D, E, F, G, H, A, 71, UINT64_C(0x1b710b35131c471b));
  R(A, B, C, D, E, F, G, H, 72, UINT64_C(0x28db77f523047d84));
  R(H, A, B, C, D, E, F, G, 73, UINT64_C(0x32caab7b40c72493));
  R(G, H, A, B, C, D, E, F, 74, UINT64_C(0x3c9ebe0a15c9bebc));
  R(F, G, H, A, B, C, D, E, 75, UINT64_C(0x431d67c49c100d4c));
  R(E, F, G, H, A, B, C, D, 76, UINT64_C(0x4cc5d4becb3e42b6));
  R(D, E, F, G, H, A, B, C, 77, UINT64_C(0x597f299cfc657e2a));
  R(C, D, E, F, G, H, A, B, 78, UINT64_C(0x5fcb6fab3ad6faec));
  R(B, C, D, E, F, G, H, A, 79, UINT64_C(0x6c44198c4a475817));

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

static void
sha512_increment(btc_sha512_t *ctx, uint64_t c) {
  ctx->size[0] += c;
  ctx->size[1] += (ctx->size[0] < c);
}

void
btc_sha512_update(btc_sha512_t *ctx, const void *data, size_t len) {
  const uint8_t *raw = (const uint8_t *)data;
  size_t pos = ctx->size[0] & 127;
  size_t want = 128 - pos;

  sha512_increment(ctx, len);

  if (len >= want) {
    if (pos > 0) {
      memcpy(ctx->block + pos, raw, want);

      raw += want;
      len -= want;
      pos = 0;

      sha512_transform(ctx, ctx->block);
    }

    while (len >= 128) {
      sha512_transform(ctx, raw);
      raw += 128;
      len -= 128;
    }
  }

  if (len > 0)
    memcpy(ctx->block + pos, raw, len);
}

void
btc_sha512_final(btc_sha512_t *ctx, uint8_t *out) {
  size_t pos = ctx->size[0] & 127;
  int i;

  ctx->block[pos++] = 0x80;

  if (pos > 112) {
    while (pos < 128)
      ctx->block[pos++] = 0x00;

    sha512_transform(ctx, ctx->block);

    pos = 0;
  }

  while (pos < 112)
    ctx->block[pos++] = 0x00;

  btc_write64be(ctx->block + 112, (ctx->size[1] << 3) | (ctx->size[0] >> 61));
  btc_write64be(ctx->block + 120, ctx->size[0] << 3);

  sha512_transform(ctx, ctx->block);

  for (i = 0; i < 8; i++)
    btc_write64be(out + i * 8, ctx->state[i]);
}

void
btc_sha512(uint8_t *out, const void *data, size_t size) {
  btc_sha512_t ctx;
  btc_sha512_init(&ctx);
  btc_sha512_update(&ctx, data, size);
  btc_sha512_final(&ctx, out);
}
